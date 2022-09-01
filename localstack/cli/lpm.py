from multiprocessing.pool import Pool
from typing import Callable, Dict

import click
from click import ClickException
from rich.console import Console

from localstack import config
from localstack.services.install import InstallerManager
from localstack.utils.bootstrap import setup_logging

console = Console()


@click.group()
def cli():
    """
    The LocalStack Package Manager (lpm) CLI is a set of commands to install third-party packages used by localstack
    service providers.

    Here are some handy commands:

    List all packages

        python -m localstack.cli.lpm list

    Install DynamoDB Local:

        python -m localstack.cli.install dynamodb-local

    Install all community packages, four in parallel:

        python -m localstack.cli.lpm list | grep "/community" | cut -d'/' -f1 | xargs python -m localstack.cli.lpm install --parallel 4
    """
    setup_logging()


def _do_install(pkg, version=None, target=None):
    console.print(f"installing... [bold]{pkg}[/bold]")
    try:
        package_installer = InstallerManager().get_installers()[pkg]
        if callable(package_installer):
            # old way
            package_installer()
        else:
            # new way
            package_installer.get_installer(version=version, target=target).install()
        console.print(f"[green]installed[/green] [bold]{pkg}[/bold]")
    except Exception as e:
        console.print(f"[red]error[/red] installing {pkg}: {e}")
        raise e


@cli.command()
@click.argument("package", nargs=-1, required=True)
@click.option(
    "--parallel",
    type=int,
    default=1,
    required=False,
    help="how many installers to run in parallel processes",
)
@click.option(
    "--version",
    type=str,
    default=None,
    required=False,
    help="WIP!! which version you want to install, just for testing!",
)
@click.option(
    "--target", type=str, default=None, required=False, help="WIP, where to install the package"
)
def install(package, parallel, version, target):
    """
    Install one or more packages.
    """
    console.print(f"resolving packages: {package}")
    installers: Dict[str, Callable] = InstallerManager().get_installers()
    config.dirs.mkdirs()

    for pkg in package:
        if pkg not in installers:
            raise ClickException(f"unable to locate installer for package {pkg}")

    if parallel > 1:
        console.print(f"install {parallel} packages in parallel:")

    # collect installers and install in parallel:
    try:
        if version or target:
            # TODO: this is just to test installing 1 package with the new installer hierarchy
            for pkg in package:
                _do_install(pkg, version, target)
        with Pool(processes=parallel) as pool:
            pool.map(_do_install, package)
    except Exception as e:
        # raise ClickException("one or more package installations failed.")
        raise e


@cli.command(name="list")
def list_packages():
    """List available packages of all repositories"""
    installers = InstallerManager()

    for repo in installers.repositories.load_all():
        for package, _ in repo.get_installer():
            console.print(f"[green]{package}[/green]/{repo.name}")


if __name__ == "__main__":
    cli()
