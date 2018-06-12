#!/bin/bash
install='No'
instal='No'
modsecu='security2_module (shared)'

zenity --info --text   "Détection des services" 
# Detection des services         
repp=$(sudo apachectl -M | grep --color security);

rep=$(man apache2);

if [[ $install == $rep* ]]; then
        
         zenity --error --text   "Aucun service" 
         exit
         
  else 
      zenity --info --text   "services présent: Apache" 
         
fi
#choix pour lintegration des regles de configuration
response=$(zenity  --list --width=350  --height=250 --text "<span color=\"blue\"> SYSTEME DE CONFIGURATION</span>"   --checklist \
   --title='SÉCURITÉ WEB'  --column=Choix --column=Vulnérabilités \
   TRUE Version TRUE "Attaque par Injection et faille XSS" TRUE "Déni de service" FALSE "Niveau de risque" --separator=':')

if [ -z "$response" ] ; then
   echo "No selection"
   exit 1
fi
#Regles de protection de version
IFS=":" ; for word in $response ; do 
   case $word in
      Version) 
 sortie=$( nmap  -sV  127.0.0.1 | grep Apache | awk '/open/{print $6}');

              LONGUEUR=${#sortie}

#securisation du fichier apache2.conf

      
        if [ $LONGUEUR != 0 ];then
                      
        
          #chown root:root /home/lemario/Documents/script/john.sh
         # chmod 4755 /home/lemario/Documents/script/john.sh
          
          echo "#protection de  version de apache2" >> /etc/apache2/apache2.conf
          echo "ServerSignature On" >> /etc/apache2/apache2.conf
          echo "ServerTokens Prod" >> /etc/apache2/apache2.conf

          #recharge du fichier pour la prise en compte des info
         /etc/init.d/apache2 force-reload
         #en cas d'echec
         
        /etc/init.d/apache2 restart
        
        #Si la apache est deja configurer 
       
      elif [ $LONGUEUR = 0 ]; then
       zenity --info --text "Version sécurisée"
        
           
        
     fi
#Regles de protection contre la faille XSS et lattaque pqr inection
 ;;
      Attaque*) 
#if  ["$repp" == "security2_module (shared)"];then
if [ ! -z "$repp" ]; then
          
           zenity --info --text "xss et injection sécurisée"
           else
                #verification de connection

                 ping -c3 www.google.com
                 connection=$?
                 if  [ $connection -ne 0 ] ; then
                   zenity --error --text "Aucune connection"
                            
                 else 
                     #installation
                  sudo apt-get update
                  sudo dpkg --configure -a
                   #apt-get install libapache-mod-security
                      sudo apt-get install libapache2-mod-security2 -y
                      #verification du chargement du module
                       # apachectl -M | grep --color security
                        #Vous devriez voir un module nommé security2_module (partagé) qui indique que le module a été chargé.
                        #renomage du fichier
                          mv /etc/modsecurity/modsecurity.conf{-recommended,}
                         
                      
                          sudo service apache2 reload
                            #configuration
                         grep -v "^SecRuleEngine" /etc/modsecurity/modsecurity.conf > fichier1.txt

                         echo  "SecRuleEngine On" >> fichier1.txt

                         cat fichier1.txt >/etc/modsecurity/modsecurity.conf
                      #  Installation de  git 
                         sudo apt install git-hub
                         git clone https://github.com/SpiderLabs/owasp-modsecurity-crs.git
                         cd owasp-modsecurity-crs
                         mv crs-setup.conf.example /etc/modsecurity/crs-setup.conf
                         mv rules/ /etc/modsecurity/
                        # mv /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
                              # prise en compte sur apache
                            service apache2 reload
                 fi
            
                 
                  
           fi

  #Regles de protection contre le deni de service      
 ;;
       Déni*)
 Tpro=$(ps -ylC apache2 | awk '{x += $8;y += 1} END {print x/((y-1)*1024)}');

 Tpra=$(expr 1 + 0${bw%.*});

 TMemo=$(free -m |grep Mem |awk '{ print $2 }');

#calcul des parametre  des regles de config

Maxclient=$(((($TMemo +$TMemo))/3))/$Tpra));
Startserver=$(((($Maxclient *3))/10));
MinSpareservers=$(((($Maxclient *5))/100));
MaxSpareservers=$(((($Maxclient *1))/10));
            zenity --info --text "fixer le nombre MAX de client a \:$Maxclient"  

            grep -v "^MaxClients" /etc/apache2/apache2.conf >fichier2.txt



#Inscription des regles dans le fichier de config de apache
            echo "MaxClients $Maxclient" >> fichier2.txt
            echo "Startservers $Startserver" >> fichier2.txt   
            echo "MinSpareserver $MinSpareservers" >> fichier2.txt
           echo "MaxSpareserver $MaxSpareservers" >> fichier2.txt
           echo "ServerLimit $Maxclient" >> fichier2.txt
           cat fichier2.txt > /etc/apache2/apache2.conf
;;
Niveau*)
zenity --info --text "pas encore"
;;
   esac
done
