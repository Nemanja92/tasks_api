<?php

require_once('db.php');
require_once('../model/Response.php');

try {
    $writeDB = DB::connectWriteDB();
} catch(PDOException $ex) {
    error_log("Connection error - ".$ex, 0);
    $response = Response::initFailure(500,"Database connection error");
    $response->send();
    exit();
}

if(array_key_exists("sessionid",$_GET)) {


} else if (empty($_GET)) {

    if($_SERVER['REQUEST_METHOD'] !== 'POST') {
        $response = Response::initFailure(405,"Request method not allowed");
        $response->send();
        exit();
    }

    // delay login by one second
    sleep(1);

    if ($_SERVER['HTTP_CONTENT_TYPE'] !== 'application/json') {
        $response = Response::initFailure(400,"Content type header not set to JSON");
        $response->send();
        exit();
    }

    $rawPostData = file_get_contents('php://input');

    if (!$jsonData = json_decode($rawPostData)) {
        $response = Response::initFailure(400,"Request body is not valid JSON");
        $response->send();
        exit();
    }

    if (!isset($jsonData->username) || !isset($jsonData->password)) {
        $response = Response::initFailure(400,null);
        (!isset($jsonData->username) ? $response->addMessage("Username field is mandatory") : false);
        (!isset($jsonData->password) ? $response->addMessage("Password field is mandatory") : false);
        $response->send();
        exit();
    }

    if (strlen($jsonData->username) < 1 || strlen($jsonData->username) > 255
        || strlen($jsonData->password) < 1 || strlen($jsonData->password) > 255){

        $response = Response::initFailure(400,null);

        (strlen($jsonData->username) < 1 ? $response->addMessage("Username cannot be blank") : false);
        (strlen($jsonData->username) > 255 ? $response->addMessage("Username cannot be greater than 255 characters") : false);

        (strlen($jsonData->password) < 1 ? $response->addMessage("Password cannot be blank") : false);
        (strlen($jsonData->password) > 255 ? $response->addMessage("Password cannot be greater than 255 characters") : false);

        $response->send();
        exit();
    }

    try {

        $username = $jsonData->username;
        $password = $jsonData->password;

        $query = $writeDB->prepare('select id, fullname, username, password, useractive, loginattempts from tblusers where username = :username');
        $query->bindParam(':username', $username, PDO::PARAM_STR);
        $query->execute();

        $rowCount = $query->rowCount();

        if ($rowCount === 0) {
            $response = Response::initFailure(401,"Username or password is incorrect");
            $response->send();
            exit();
        }

        $row = $query->fetch(PDO::FETCH_ASSOC);

        $returned_id = $row['id'];
        $returned_fullname = $row['fullname'];
        $returned_username = $row['username'];
        $returned_password = $row['password'];
        $returned_useractive = $row['useractive'];
        $returned_loginattempts = $row['loginattempts'];

        if ($returned_useractive !== 'Y') {
            $response = Response::initFailure(401,"User account not active");
            $response->send();
            exit();
        }

        if ($returned_loginattempts >= 3) {
            $response = Response::initFailure(401,"User account is currently locked out");
            $response->send();
            exit();
        }

        // verify if users input password (plain text) is matching password in database (hashed)
        if(!password_verify($password, $returned_password)) {
            $query = $writeDB->prepare('update tblusers set loginattempts = loginattempts+1 where id = :id');
            $query->bindParam(':id', $returned_id, PDO::PARAM_INT);
            $query->execute();

            $response = Response::initFailure(401,"Username or password is incorrect");
            $response->send();
            exit();
        }

        // generate tokens
        $accesstoken = base64_encode(bin2hex(openssl_random_pseudo_bytes(24)).time());
        $refreshtoken = base64_encode(bin2hex(openssl_random_pseudo_bytes(24)).time());

        $access_token_expiry_seconds = 1200; // 20 minutes
        $refresh_token_expiry_seconds = 1209600; // 14 days

    } catch(PDOException $ex) {
        $response = Response::initFailure(500,"There was an issue logging in, please try again");
        $response->send();
        exit();
    }

    try {
        $writeDB->beginTransaction();

        $query = $writeDB->prepare('update tblusers set loginattempts = 0 where id = :id');
        $query->bindParam(':id', $returned_id, PDO::PARAM_INT);
        $query->execute();

        $query = $writeDB->prepare('insert into tblsessions (userid, accesstoken, accesstokenexpiry, refreshtoken, refreshtokenexpiry) values (:userid, :accesstoken, date_add(NOW(), INTERVAL :accesstokenexpiryseconds SECOND), :refreshtoken, date_add(NOW(), INTERVAL :refreshtokenexpiryseconds SECOND))');
        $query->bindParam(':userid', $returned_id, PDO::PARAM_INT);
        $query->bindParam(':accesstoken', $accesstoken, PDO::PARAM_STR);
        $query->bindParam(':accesstokenexpiryseconds', $access_token_expiry_seconds, PDO::PARAM_INT);
        $query->bindParam(':refreshtoken', $accesstoken, PDO::PARAM_STR);
        $query->bindParam(':refreshtokenexpiryseconds', $refresh_token_expiry_seconds, PDO::PARAM_INT);
        $query->execute();

        $lastSessionID = $writeDB->lastInsertId();

        // saves the data into database
        $writeDB->commit();

        $returnData = array();
        $returnData['session_id'] = intval($lastSessionID);
        $returnData['access_token'] = $accesstoken;
        $returnData['access_token_expires_in'] = $access_token_expiry_seconds;
        $returnData['refresh_token'] = $refreshtoken;
        $returnData['refresh_token_expires_in'] = $refresh_token_expiry_seconds;

        $response = Response::initSuccess(201,"Login successfull",$returnData,false);
        $response->send();
        exit();


    } catch(PDOException $ex) {
        // undo or restore database transactioin
        $writeDB->rollBack();
        $response = Response::initFailure(500,"There was an issue logging in, please try again");
        $response->send();
        exit();
    }

} else {
    $response = Response::initFailure(404,"Endpoint not found");
    $response->send();
    exit();
}




