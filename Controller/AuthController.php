<?php

class AuthController extends AppController {


    public function getClientToken() {
        // Just generating a random client token and returning it
        return sprintf( '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand( 0, 0xffff ),
            mt_rand( 0, 0xffff ),
            mt_rand( 0, 0xffff ),
            mt_rand( 0, 0x0fff ) | 0x4000,
            mt_rand( 0, 0x3fff ) | 0x8000,
            mt_rand( 0, 0xffff ),
            mt_rand( 0, 0xffff ),
            mt_rand( 0, 0xffff )
        );
    }

    function decryptPass($username, $password) {
        
        if(strpos($username, '@')) {
            $conditions = array("User.email"  => array($username));
        } else {
            $conditions = array("User.pseudo"  => array($username));
        }

        $userFound = $this->User->find('first', array('conditions' => $conditions));
        $key = $userFound["User"]["private-key"];

        $method = 'aes-256-cbc';

        $iv = chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0);
        
        $decrypted = openssl_decrypt(base64_decode($password), $method, $key, OPENSSL_RAW_DATA, $iv);
        
        return $decrypted;
    }

    //length 32 for 32bit decrypt
    function generateKey($username, $length = 32) {

        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $charactersLength = strlen($characters);
        $result = '';
        for ($i = 0; $i < $length; $i++) {
            $result .= $characters[rand(0, $charactersLength - 1)];
        }

        if(strpos($username, '@')) {
            $conditions = array("User.email"  => array($username));
        } else {
            $conditions = array("User.pseudo"  => array($username));
        }

        $userFound = $this->User->find('first', array('conditions' => $conditions));
        $this->User->read(null, $userFound['User']['id']);
        $this->User->set('private-key', $result);
        $this->User->save();

        return $result;

    }

    function error($message) {
        $json->error->message = $message;
        return json_encode($json);
    }

    public function getPrivateKey(){

        $isPost = $this->request->is('post');

        $username = $this->params['url']['username'];

        $user_agent = $_SERVER['HTTP_USER_AGENT'];

        if($user_agent == null || $user_agent != "MinewebAuth authenticator") {echo $this->error('Missing user agent'); exit;}

        if($isPost) {
            //$this->generateKey();

            if(strpos($username, '@')) {
                $conditions = array("User.email"  => array($username));
            } else {
                $conditions = array("User.pseudo"  => array($username));
            }
    
            $userFound = $this->User->find('first', array('conditions' => $conditions));

            if($userFound["User"]["private-key"] == null) {
                $json->key = $this->generateKey($username);
                echo json_encode($json);
                exit;
            }
            $json->key = $userFound["User"]["private-key"];
            echo json_encode($json);
            exit;
        }

    }

    public function authenticate()
    {
        $isPost = $this->request->is('post');

        if(!$isPost) {echo 'Only POST requests are accepted'; exit;}

        $this->loadModel('User');
        $this->loadModel('Ban');
        
        $username = $this->params['url']['username'];
        $password = $this->params['url']['password'];

        $user_agent = $_SERVER['HTTP_USER_AGENT'];

        if($user_agent == null || $user_agent != "MinewebAuth authenticator") {echo $this->error('Missing user agent'); exit;}

        if(strpos($username, '@')) {
            $conditions = array("User.email"  => array($username));
            $userFound = $this->User->find('first', array('conditions' => $conditions));
            $username = $userFound["User"]["pseudo"];
        }

        $passwordInDB = $this->User->getFromUser('password', $username);

        if(empty($username) || empty($password)) {echo $this->error('Missing arguments'); exit;}
        if (crypt($this->decryptPass($username, $password), $passwordInDB) == $passwordInDB)
        {
            //connected
            $user = $this->User->getAllFromUser($username);
            $userId = $user['id'];

            $conditions = array("Ban.user_id"  => array($user['id']));
            $userFound = $this->Ban->find('first', array('conditions' => $conditions));

            if(count($userFound) == 1){
                echo $this->error('user_banned, reason: '.$userFound["Ban"]["reason"]);
                exit;
            }

            if(empty($user['uuid'])){
                $uuid = md5($user["pseudo"]);
                $this->User->setToUser("uuid", $uuid, $userId);
            }

            $accessToken = md5(uniqid(rand(), true));
            $clientToken = $this->getClientToken();

            $this->User->setToUser('auth-accessToken', $accessToken, $userId);

            $this->User->setToUser('auth-clientToken', $clientToken, $userId);


            $this->User->save();

            $json->data->id = $user['id'];
            $json->data->pseudo = $user['pseudo'];
            $json->data->email = $user['email'];
            $json->data->rank = $user['rank'];
            $json->data->money = $user['money'];
            $json->data->ip = $user['ip'];
            $json->data->created = $user['created'];
            $json->data->confirmed = $user['confirmed'] != null;
            $json->data->uuid = $user['uuid'];
            $json->data->accessToken = $accessToken;
            $json->data->clientToken = $clientToken;

            echo json_encode($json);
            $this->generateKey($username);
        } else {
            echo $this->error("Mauvais identifiants");
        }
        exit;
    }

    public function refresh() {

        $isPost = $this->request->is('post');

        if(!$isPost) {echo 'Only POST requests are accepted'; exit;}

        $this->loadModel('User');
        
        $accessToken = $this->params['url']['accessToken'];
        $clientToken = $this->params['url']['clientToken'];

        $user_agent = $_SERVER['HTTP_USER_AGENT'];

        if($user_agent == null || $user_agent != "MinewebAuth authenticator") {echo $this->error('Missing user agent'); exit;}

        if(empty($accessToken) || empty($clientToken)) {echo $this->error('Missing arguments'); exit;}

        $conditions = array("User.auth-accessToken"  => array($accessToken));
        $userFound = $this->User->find('first', array('conditions' => $conditions));

        if($userFound == null) {
            echo $this->error("Token invalide");
            exit;
        }

        if($clientToken == $userFound["User"]["auth-clientToken"]) {
            $user = $this->User->getAllFromUser($userFound["User"]["pseudo"]);

            $clientToken = $this->getClientToken();
            $accessToken = md5(uniqid(rand(), true));

            $this->User->setToUser('auth-accessToken', $accessToken, $user['id']);
            $this->User->setToUser("auth-clientToken", $clientToken, $user['id']);
            $this->User->save();

            $json->data->id = $user['id'];
            $json->data->pseudo = $user['pseudo'];
            $json->data->email = $user['email'];
            $json->data->rank = $user['rank'];
            $json->data->money = $user['money'];
            $json->data->ip = $user['ip'];
            $json->data->created = $user['created'];
            $json->data->confirmed = $user['confirmed'] != null;
            $json->data->uuid = $user['uuid'];
            $json->data->accessToken = $accessToken;
            $json->data->clientToken = $clientToken;

            echo json_encode($json);

            exit;

        } else {
            echo $this->error("Token invalide");
            exit;
        }


    }


    public function invalidate() {

        $isPost = $this->request->is('post');

        if(!$isPost) {echo 'Only POST requests are accepted'; exit;}

        $this->loadModel('User');
        
        $accessToken = $this->params['url']['accessToken'];
        $clientToken = $this->params['url']['clientToken'];

        $user_agent = $_SERVER['HTTP_USER_AGENT'];

        if($user_agent == null || $user_agent != "MinewebAuth authenticator") {echo $this->error('Missing user agent'); exit;}

        if(empty($accessToken) || empty($clientToken)) {echo $this->error('Missing arguments'); exit;}

        $conditions = array("User.auth-accessToken"  => array($accessToken));
        $userFound = $this->User->find('first', array('conditions' => $conditions));

        if($userFound == null) {
            echo $this->error("Token already invalide");
            exit;
        }

        if($clientToken == $userFound["User"]["auth-clientToken"]) {
            $user = $this->User->getAllFromUser($userFound["User"]["pseudo"]);

            $this->User->setToUser('auth-accessToken', "", $user['id']);
            $this->User->setToUser("auth-clientToken", "", $user['id']);
            $this->User->save();

            $json->succes = "ok";
            echo json_encode($json); 
            exit;

        } else {
            echo $this->error("Token already invalide");
            exit;
        }

    }

    public function version()
    {
        $config = json_decode(file_get_contents("../../app/Plugin/Auth/config.json"), true);
        echo 'AuthMineweb OK - Version '.$config['version'];
        exit;
    }

}
