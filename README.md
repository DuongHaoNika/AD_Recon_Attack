## Active Directory Attack Tool (version 1.1)

### Usage:

Clone this repository:

```
git clone https://github.com/it-sec-vf/ads.git
```

Install dependencies

```
pip install -r requirements.txt
```

Using:

```
python3 main.py <OPTIONS>
```
Example: `python3 main.py attack --help`

__Features:__

- Lists all users, groups, users in groups
- List all GPOs, OUs, GPOs linked OUs
- List all domain controllers
- List all DNS Record
- Check Domain Controller support with NTLM Hash
- Scan GPO misconfiguration
- Get NTLM Hash
- Pass The Hash Attack

