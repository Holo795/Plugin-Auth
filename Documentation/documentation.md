# AuthMineweb
- Ce plugin vous permettra de mettre une authentification personnalisé
sur votre Launcher

<h1>Installation :  
  
  
## Web | FTP
- Cliquez sur "Clone or download" sur la page "https://github.com/Holo795/Plugin-Auth/".
- Téléchargez et enregistrez le ZIP, puis extrayez le.
- Renommez le fichier "Mineweb_Plugin-Auth-master" par "Auth".
- Déplacez le fichier dans votre FTP à l'adresse "/app/Plugin".
- Supprimez tous les fichiers dans le "/app/tmp/cache" de votre FTP.
- Installation effectuée. 
##  
  
## Java | Launcher
- Ajoutez la librairie Java "[AuthMineweb_1.4.0.jar](https://github.com/Holo795/Plugin-Auth/raw/master/Documentation/AuthMineweb_1.4.0.jar)" à votre projet.

###  Exemples :
 
Connexion avec Username et Password :
```java
public static void auth(String username, String password) {

	AuthMineweb authenticator = new AuthMineweb("http://localhost/");
	AuthResponse response = authenticator.authenticate(username, password);
	authInfos = new AuthInfos(response.getPseudo(), response.getAccessToken(), response.getClientToken(), response.getUuid());

}
```
   
Connexion AccessToken et ClientToken :
```java
public static void reauth(String accessToken, String clientToken) {

	AuthMineweb authenticator = new AuthMineweb("http://localhost/");
	AuthResponse response = authenticator.refresh(accessToken, clientToken);
	authInfos = new AuthInfos(response.getPseudo(), response.getAccessToken(), response.getClientToken(), response.getUuid());

}
```
##
