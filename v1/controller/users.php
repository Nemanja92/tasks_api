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

if($_SERVER['REQUEST_METHOD'] !== 'POST') {
    $response = Response::initFailure(405,"Request method not allowed");
    $response->send();
    exit();
}

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

if (!isset($jsonData->fullname) || !isset($jsonData->username) || !isset($jsonData->password)) {
    $response = Response::initFailure(400,null);
    (!isset($jsonData->fullname) ? $response->addMessage("Full name field is mandatory") : false);
    (!isset($jsonData->username) ? $response->addMessage("Username field is mandatory") : false);
    (!isset($jsonData->password) ? $response->addMessage("Password field is mandatory") : false);
    $response->send();
    exit();
}

if (strlen($jsonData->fullname) < 1 || strlen($jsonData->fullname) > 255
    || strlen($jsonData->username) < 1 || strlen($jsonData->username) > 255
    || strlen($jsonData->password) < 1 || strlen($jsonData->password) > 255){

    $response = Response::initFailure(400,null);
    (strlen($jsonData->fullname) < 1 ? $response->addMessage("Full name cannot be blank") : false);
    (strlen($jsonData->fullname) > 255 ? $response->addMessage("Full name cannot be greater than 255 characters") : false);

    (strlen($jsonData->username) < 1 ? $response->addMessage("Username cannot be blank") : false);
    (strlen($jsonData->username) > 255 ? $response->addMessage("Username cannot be greater than 255 characters") : false);

    (strlen($jsonData->password) < 1 ? $response->addMessage("Password cannot be blank") : false);
    (strlen($jsonData->password) > 255 ? $response->addMessage("Password cannot be greater than 255 characters") : false);

    $response->send();
    exit();

}

$fullname = trim($jsonData->fullname);
$username = trim($jsonData->username);
$password = $jsonData->password;

try {
    $query = $writeDB->prepare('select id from tblusers where username = :username');
    $query->bindParam(':username', $username, PDO::PARAM_STR);
    $query->execute();

    $rowCount = $query->rowCount();

    if ($rowCount !== 0) {
        $response = Response::initFailure(409,"Username already exist");
        $response->send();
        exit();
    }

    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    $query = $writeDB->prepare('insert into tblusers (fullname, username, password) values (:fullname, :username, :password)');
    $query->bindParam(':fullname', $fullname, PDO::PARAM_STR);
    $query->bindParam(':username', $username, PDO::PARAM_STR);
    $query->bindParam(':password', $hashed_password, PDO::PARAM_STR);
    $query->execute();

    $rowCount = $query->rowCount();

    if ($rowCount === 0) {
        $response = Response::initFailure(500,"There was an issue creating a user account, please try again");
        $response->send();
        exit();
    }

    $lastUserID = $writeDB->lastInsertId();

    $returnData = array();
    $returnData['user_id'] = $lastUserID;
    $returnData['fullname'] = $fullname;
    $returnData['username'] = $username;

    $response = Response::initSuccess(201,"User created successfully",$returnData,false);
    $response->send();
    exit();

} catch(PDOException $ex) {
    error_log("Database query error - ".$ex, 0);
    $response = Response::initFailure(500,"There was an issue creating a user account, please try again");
    $response->send();
    exit();
}
