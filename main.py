from dotenv import load_dotenv
load_dotenv()

from scanner.cli import cli

if __name__ == "__main__":
    cli()