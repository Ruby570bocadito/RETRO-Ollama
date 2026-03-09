
#!/bin/bash

# Eliminar temporales
find /tmp -type f -exec rm {} \;

# Eliminar logs
find /var/log -type f -name "*.log" -exec rm {} \;

# Eliminar sesiones de usuarios
find /tmp -type f -name "*.X*" -exec rm {} \;

# Eliminar sesiones de aplicaciones
find /tmp -type f -name "*.s*" -exec rm {} \;

# Actualizar el sistema
sudo apt-get update && sudo apt-get dist-upgrade -y

# Reiniciar servicios
sudo service apache2 restart
sudo service mysql restart
sudo service postfix restart

# Eliminar paquetes inutiles
sudo apt-get autoremove -y
sudo apt-get autoclean -y
