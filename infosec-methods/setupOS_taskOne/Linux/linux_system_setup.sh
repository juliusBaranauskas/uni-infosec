# 1. Sistemų administratorius (God), [sysadmin]
# 2. Vadovas (Boss), [director]
# 3. Administracija (Fin1 ir Fin2), [administration]
# 4. Vadybininkai (Man1, Man2, Man3, Man4), [manager]
# 5. Nežiniukas (Supreme). [peasant]


# cleanup
userdel God
userdel Boss
userdel Fin1
userdel Fin2
userdel Man1
userdel Man2
userdel Supreme

groupdel sysadmin
groupdel director
groupdel administration
groupdel manager
groupdel peasant
groupdel employee

rm -rf /bendrove

# Begin setup
groupadd sysadmin
groupadd director
groupadd administration
groupadd manager        
groupadd peasant
groupadd employee

# Create users and remove passwords for them
useradd -d /bendrove -g sysadmin God
passwd -d God

useradd -d /bendrove/boss -g director -G employee Boss
passwd -d Boss

useradd -d /bendrove/administracija/fin1/ -g administration -G employee Fin1
passwd -d Fin1

useradd -d /bendrove/administracija/fin2/ -g administration -G employee Fin2
passwd -d Fin2

useradd -d /bendrove/vadovai/man1 -g manager -G employee Man1
passwd -d Man1

useradd -d /bendrove/vadovai/man1 -g manager -G employee Man2
passwd -d Man2

useradd -d /bendrove -g peasant -G employee Supreme
passwd -d Supreme

# Kuriam direktorijas
mkdir -p /bendrove
setfacl -m user::---,group::---,other:---,group:employee:r-x,default:user::rwx,default:g::r-x /bendrove

setfacl -m group:director:rwx,group:sysadmin:rwx,default:group:sysadmin:rwx,default:group:director:rwx /bendrove

mkdir -p /bendrove/boss
setfacl -m user::---,group::---,other:---,group:director:rwx,default:user::rwx,default:g::rwx /bendrove/boss
chown Boss:director /bendrove/boss


# Administracijos kampelis
mkdir -p /bendrove/administracija
setfacl -m user::---,group::---,other::---,group:administration:r-x,default:group:administration:r-x /bendrove/administracija
chown root:administration /bendrove/administracija

mkdir -p /bendrove/administracija/fin1
setfacl -m u::rwx,default:user::rwx /bendrove/administracija/fin1
chown Fin1:administration /bendrove/administracija/fin1

# add higher-in-hierarchy groups permissions
# setfacl -m group:director:rwx,group:sysadmin:rwx,default:group:sysadmin:rwx,default:group:director:rwx /bendrove/administracija/fin1
# chmod +t /bendrove/administracija/fin1

mkdir -p /bendrove/administracija/fin2
setfacl -m u::rwx,default:user::rwx /bendrove/administracija/fin2
chown Fin2:administration /bendrove/administracija/fin2



# Vadybininku kampelis
mkdir -p /bendrove/vadovai
setfacl -m user::---,group::---,other::---,group:manager:r-x,default:group:manager:r-x /bendrove/vadovai
chown root:manager /bendrove/vadovai

mkdir -p /bendrove/vadovai/man1
setfacl -m u::rwx,default:user::rwx /bendrove/vadovai/man1
chown Man1:manager /bendrove/vadovai/man1

mkdir -p /bendrove/vadovai/man2
setfacl -m u::rwx,default:user::rwx /bendrove/vadovai/man2
chown Man2:manager /bendrove/vadovai/man2


# visi daro ka nori
mkdir -p /bendrove/chaoso_kambarelis
setfacl -m g:employee:rwx,other:---,default:g:employee:rwx,default:u::rwx /bendrove/chaoso_kambarelis


# prieinamas tik tam tikriems vartotojams
mkdir -p /bendrove/meme_club
setfacl -m other:---,user:Fin1:rwx,user:Man1:rwx /bendrove/meme_club
chmod +t /bendrove/meme_club


# Task #2
setfacl -m user:Fin2:rwx /bendrove/boss

# Task #3
sudo cp /etc/pam.d/common-password /etc/pam.d/common-password.backup
sudo cp common-password.upgrade /etc/pam.d/common-password

sudo cp /etc/login.defs /etc/login.defs.backup
sudo cp login.defs.better /etc/login.defs


# Task #4
setfacl -m group:administration:r-- /usr/bin/zip

setfacl -m group:employee:r-- /usr/bin/gnome-terminal
setfacl -m group:employee:r-- /usr/bin/gnome-terminal.real
setfacl -m group:employee:r-- /usr/bin/gnome-terminal.wrapper

setfacl -m group:employee:r-- /usr/bin/ip


# Task #6
ownerName="Fin1"
filename="transferOwnership.test"
newOwner="Fin2"

su - $ownerName -c "touch $filename"
homedir=$( getent passwd "$ownerName" | cut -d: -f6 )
chown $newOwner "$homedir$filename"

