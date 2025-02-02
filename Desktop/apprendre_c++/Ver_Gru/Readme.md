Ce projet à pour but d'être strictement éducatif je ne suis en aucun cas responsable des actions commisses vien le programme que je fournis

Prérequis

Système d'exploitation : Windows 10 ou plus récent

Compilateur : MinGW, GCC ou Microsoft Visual Studio (recommandé)

Accès administrateur pour l'installation des dépendances

Bibliothèques Utilisées

<windows.h> : Inclus dans le SDK Windows, installé par défaut avec Visual Studio.

<iphlpapi.h> : Inclus dans le SDK Windows. Lier avec Iphlpapi.lib.

<lm.h> : Inclus dans le SDK Windows. Lier avec Netapi32.lib.

<curl/curl.h> : Bibliothèque externe cURL.

<tlhelp32.h> : Inclus dans le SDK Windows.

, , , , , , , ,  : Parties de la bibliothèque standard C++.

Installation des Dépendances

1. SDK Windows

Installer Visual Studio : https://visualstudio.microsoft.com/

Pendant l'installation, sélectionner « Desktop development with C++ ».

2. cURL

Télécharger cURL pour Windows : https://curl.se/windows/

Extraire les fichiers et ajouter le chemin de lib et include à votre environnement.

Lors de la compilation, lier avec libcurl.lib ou -lcurl.

3. Configuration du Compilateur

Pour GCC (MinGW) :

 g++ -o mon_programme.exe mon_programme.cpp -liphlpapi -lnetapi32 -lcurl


Variables d'Environnement

Assurez-vous que les chemins vers les dossiers include et lib de cURL sont ajoutés dans les variables d'environnement :

INCLUDE : C:\path\to\curl\include

LIB : C:\path\to\curl\lib

Commande de compilation du programme:
 g++ -o worm.exe worm5.cpp -I "C:\curl\curl\include" -L "C:\curl\curl\lib" -lcurl -lws2_32 -liphlpapi -lnetapi32

Caractèristiques:

 - Méthode j'injection via un process légitime
 - Utilisation de l'encodage XOR 
 - Utilisation de l'API Windows
 - Utilisation de la bibliothèque cURL pour envoyé des informations à un bot telegram
 - Recherche d'un process en particulier
 - Propagation via les patages smb sans protection 
