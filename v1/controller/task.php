<?php
require_once('db.php');
require_once('../model/Task.php');
require_once('../model/Response.php');

try {
  $writeDB = DB::connectWriteDB();
  $readDB = DB::connectReadDB();
} catch(PDOException $ex) {
  error_log("Connection error - ".$ex, 0);
  $response = new Response();
  $response->setHttpStatusCode(500);
  $response->setSuccess(false);
  $response->addMessage("Database connection error");
  $response->send();
  exit();
}

if(array_key_exists("taskid",$_GET)) {

  $taskid = $_GET['taskid'];
  if($taskid == '' || !is_numeric($taskid)) {
    $response = Response::initFailure(400,"Task ID cannot be blank or must be numeric");
    $response->send();
    exit();
  }

  if($_SERVER['REQUEST_METHOD'] === 'GET') {

    try {
      $query = $readDB->prepare('select id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") as deadline, completed from tbltasks where id = :taskid');
      $query->bindParam(':taskid', $taskid, PDO::PARAM_INT);
      $query->execute();

      $rowCount = $query->rowCount();

      if($rowCount === 0) {
        $response = Response::initFailure(404,"Task not found");
        $response->send();
        exit();
      }

      while($row = $query->fetch(PDO::FETCH_ASSOC)) {
        $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);
        $taskArray[] = $task->returnTaskArray();
      }

      $returnData = array();
      $returnData['rows_returned'] = $rowCount;
      $returnData['tasks'] = $taskArray;
      $response = Response::initSuccess(200,"Data fetched successfully",$returnData,true);
      $response->send();
      exit();
    } catch (TaskException $ex) {
      $response = Response::initFailure(500,$ex->getMessage());
      $response->send();
      exit();
    } catch (PDOException $ex) {
      error_log("Database query error - ".$ex, 0);
      $response = Response::initFailure(500,"Failed to get task");
      $response->send();
      exit();
    }

  } else if ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
    try {

      $query = $writeDB->prepare('delete from tbltasks where id = :taskid');
      $query->bindParam(':taskid', $taskid, PDO::PARAM_INT);
      $query->execute();

      $rowCount = $query->rowCount();

      if ($rowCount === 0) {
        $response = Response::initFailure(404,"Task not found");
        $response->send();
        exit;
      }

      $response = Response::initSuccess(200,"Task deleted successfully",null,false);
      $response->send();
      exit;

    } catch (PDOException $ex) {
      $response = Response::initFailure(500,"Failed to delete task");
      $response->send();
      exit;
    }
  } else if ($_SERVER['REQUEST_METHOD'] === 'PATCH') {

  } else {
    $response = Response::initFailure(405,"Request method not allowed");
    $response->send();
    exit();
  }

} else if (array_key_exists("completed",$_GET)) {

  $completed = $_GET['completed'];

  if ($completed !== 'Y' && $completed !== 'N') {
    $response = Response::initFailure(400,"Completed folter must be Y or N");
    $response->send();
    exit();
  }

  if ($_SERVER['REQUEST_METHOD'] === 'GET') {

    try {

      $query = $readDB->prepare('select id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") as deadline, completed from tbltasks where completed = :completed');
      $query->bindParam(':completed', $completed, PDO::PARAM_STR);
      $query->execute();

      $rowCount = $query->rowCount();

      $taskArray = array();

      while($row = $query->fetch(PDO::FETCH_ASSOC)) {
        $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);
        $taskArray[] = $task->returnTaskArray();
      }

      $returnData = array();
      $returnData['rows_returned'] = $rowCount;
      $returnData['tasks'] = $taskArray;
      $response = Response::initSuccess(200,"Data fetched successfully",$returnData,true);
      $response->send();
      exit();

    } catch (TaskException $ex) {
      $response = Response::initFailure(500,$ex->getMessage());
      $response->send();
      exit();
    } catch (PDOException $ex) {
      error_log("Database query error - ".$ex, 0);
      $response = Response::initFailure("Failed to get tasks");
      $response->send();
      exit();
    }


  } else {
    $response = Response::initFailure(405,"Request method not allowed");
    $response->send();
    exit();
  }

}


 ?>
