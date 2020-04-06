<?php

class SessionException extends Exception {}

class Session {

    private $_id;
    private $_accessToken;
    private $_accessTokenExpiry;
    private $_refreshToken;
    private $_refreshTokenExpiry;

    public function __construct($id, $accessToken, $accessTokenExpiry, $refreshToken, $refreshTokenExpiry) {
        $this->setID($id);
        $this->setAccessToken($accessToken);
        $this->setAccessTokenExpiry($accessTokenExpiry);
        $this->setRefreshToken($refreshToken);
        $this->setRefreshTokenExpiry($refreshTokenExpiry);
    }

    public function getID() {
        return $this->_id;
    }

    public function getAccessToken() {
        return $this->_accessToken;
    }

    public function getAccessTokenExpiry() {
        return $this->_accessTokenExpiry;
    }

    public function getRefreshToken() {
        return $this->_refreshToken;
    }

    public function getRefreshTokenExpiry() {
        return $this->_refreshTokenExpiry;
    }

    public function setID($id) {
        if(($id !== null) && (!is_numeric($id) || $id <= 0 || $id > 9223372036854775807 || $this->_id !== null)) {
            throw new TaskException("Session ID error");
        }
        $this->_id = $id;
    }

    public function setAccessToken($accessToken) {
        $this->_accessToken = $accessToken;
    }

    public function setAccessTokenExpiry($accessTokenExpiry) {
        $this->_accessTokenExpiry = $accessTokenExpiry;
    }

    public function setRefreshToken($refreshToken) {
        $this->_refreshToken = $refreshToken;
    }

    public function setRefreshTokenExpiry($refreshTokenExpiry) {
        $this->_refreshTokenExpiry = $refreshTokenExpiry;
    }

    public function returnSessionArray() {
        $session = array();
        $session['id'] = $this->getID();
        $session['accessToken'] = $this->getAccessToken();
        $session['accessTokenExpiry'] = $this->getAccessTokenExpiry();
        $session['refreshToken'] = $this->getRefreshToken();
        $session['refreshTokenExpiry'] = $this->getRefreshTokenExpiry();
        return $session;
    }



}


?>
