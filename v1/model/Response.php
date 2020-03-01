<?php

  class Response {

    private $_success;
    private $_httpStatusCode;
    private $_messages = array();
    private $_data;
    private $_toCache = false;
    private $_responseData = array();

    public function __construct() {
    // allocate your stuff
    }

    // custom initialization, since we want to keep both, original __construct and this one
    // we need __construct in case we want to initialize Response without params
    public function init($success, $httpStatusCode, $messages, $data, $toCache) {
      $instance = new self();
      $instance->_success = $success;
      $instance->_httpStatusCode = $httpStatusCode;
      $instance->_messages[] = $messages;
      $instance->_data = $data;
      $instance->_toCache = $toCache;
      return $instance;
    }

    public function initSuccess($httpStatusCode, $messages, $data, $toCache) {
      $instance = new self();
      $instance->_success = true;
      $instance->_httpStatusCode = $httpStatusCode;
      $instance->_messages[] = $messages;
      $instance->_data = $data;
      $instance->_toCache = $toCache;
      return $instance;
    }

    public function initFailure($httpStatusCode, $messages) {
      $instance = new self();
      $instance->_success = false;
      $instance->_httpStatusCode = $httpStatusCode;
      $instance->_messages[] = $messages;
      $instance->_data = null;
      $instance->_toCache = false;
      return $instance;
    }

    public function setSuccess($success) {
      $this->_success = $success;
    }

    public function setHttpStatusCode($httpStatusCode) {
      $this->_httpStatusCode = $httpStatusCode;
    }

    public function addMessage($message) {
      $this->_messages[] = $message;
    }

    public function setData($data) {
      $this->_data = $data;
    }

    public function toCache($toCache) {
      $this->_toCache = $toCache;
    }

    public function send() {

      header('Content-type: application/json;charset=utf-8');

      if ($this->_toCache == true) {
        header('Cache-control: max-age=60');
      } else {
        header('Cache-control: no-cache, no-store');
      }

      if(($this->_success !== false && $this->_success !== true) || !is_numeric($this->_httpStatusCode)) {
        http_response_code(500);
        $this->_responseData['statusCode'] = 500;
        $this->_responseData['success'] = false;
        $this->addMessage("Response creation error");
        $this->_responseData['messages'] = $this->_messages;
      } else {
        http_response_code($this->_httpStatusCode);
        $this->_responseData['statusCode'] = $this->_httpStatusCode;
        $this->_responseData['success'] = $this->_success;
        $this->_responseData['messages'] = $this->_messages;
        $this->_responseData['data'] = $this->_data;
      }

      echo json_encode($this->_responseData);

    }

  }



 ?>
