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
            $response = Response::initFailure(400,"Task completed must be Y or N");
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
        
    } else if (array_key_exists("page",$_GET)){
        
        if ($_SERVER['REQUEST_METHOD'] === 'GET') {
            
            $page = $_GET['page'];
            
            if ($page == '' || !is_numeric($page)) {
                $response = Response::initFailure(400,"Page number cannot be blank and must be numeric");
                $response->send();
                exit();
            }
            
            $limitPerPage = 20;
            
            try {
                
                $query = $readDB->prepare('select count(id) as totalNoOfTasks from tbltasks');
                $query->execute();
                $row = $query->fetch(PDO::FETCH_ASSOC);
                $tasksCount = intval($row['totalNoOfTasks']);
                
                $numOfPages = ceil($tasksCount/$limitPerPage);
                
                if ($numOfPages == 0) {
                    $numOfPages = 1;
                }
                
                if ($page > $numOfPages || $page == 0) {
                    $response = Response::initFailure(404,"Page not found");
                    $response->send();
                    exit();
                }
                
                $offset = ($page == 1 ? 0 : ($limitPerPage*($page-1)));
                $query = $readDB->prepare('select id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") as deadline, completed from tbltasks limit :pglimit offset :offset');
                $query->bindParam(':pglimit',$limitPerPage, PDO::PARAM_INT);
                $query->bindParam(':offset',$offset, PDO::PARAM_INT);
                $query->execute();
                
                $rowCount = $query->rowCount();
                
                $taskArray = array();
                while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
                    $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);
                    $taskArray[] = $task->returnTaskArray();
                }
                
                $returnData = array();
                $returnData['rows_returned'] = $rowCount;
                $returnData['total_rows'] = $tasksCount;
                $returnData['total_pages'] = $numOfPages;
                ($page < $numOfPages ? $returnData['has_next_page'] = true : $returnData['has_next_page'] = false);
                ($page > 1 ? $returnData['has_previous_page'] = true : $returnData['has_previous_page'] = false);
                $returnData['tasks'] = $taskArray;
                $response = Response::initSuccess(200,"Data fetched successfully",$returnData,true);
                $response->send();
                exit();
            } catch (TaskException $ex) {
                $response = Response::initFailure(500,$ex->getMessage());
                $response->send();
                exit();
            } catch (PDOException $ex) {
                error_log("Database querry error - ".$ex);
                $response = Response::initFailure(500,"Failed to get tasks");
                $response->send();
                exit();
            }
            
            
        } else {
            $response = Response::initFailure(405,"Request method not allowed");
            $response->send();
            exit();
        }
        
        
    } else if (empty($_GET)) {
        
        if ($_SERVER['REQUEST_METHOD'] === 'GET') {
            try {
                $query = $readDB->prepare('select id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") as deadline, completed from tbltasks');
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
                $response = Response::initFailure(500,"Failed to get task");
                $response->send();
                exit();
            }
        } else if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            
            
            try {
                
                if ($_SERVER['HTTP_CONTENT_TYPE'] !== 'application/json') {
                    $response = Response::initFailure(400,"Content type header is not set to JSON");
                    $response->send();
                    exit();
                }
                
                $rawPOSTData = file_get_contents('php://input');
                
                if (!$jsonData = json_decode($rawPOSTData)) {
                    $response = Response::initFailure(400,"Request body is not valid JSON");
                    $response->send();
                    exit();
                }
                
                if (!isset($jsonData->title) || !isset($jsonData->completed)) {
                    $response = Response::initFailure(400,null);
                    (!isset($jsonData->title) ? $response->addMessage("Title field is mandatory") : false);
                    (!isset($jsonData->completed) ? $response->addMessage("Completed field is mandatory") : false);
                    $response->send();
                    exit();
                }
                
                $descParam = isset($jsonData->description) ? $jsonData->description : null;
                $deadlineParam = isset($jsonData->deadline) ? $jsonData->deadline : null;
                
                $newTask = new Task(null, $jsonData->title, $descParam, $deadlineParam, $jsonData->completed);
                
                
                
                $title = $newTask->getTitle();
                $description = $newTask->getDescription();
                $deadline = $newTask->getDeadline();
                $completed = $newTask->getCompleted();
                
                $query = $writeDB->prepare('insert into tbltasks (title, description, deadline, completed) values (:title, :description, STR_TO_DATE(:deadline, "%d/%m/%Y %H:%i"), :completed)');
                $query->bindParam(':title', $title, PDO::PARAM_STR);
                $query->bindParam(':description', $description, PDO::PARAM_STR);
                $query->bindParam(':deadline', $deadline, PDO::PARAM_STR);
                $query->bindParam(':completed', $completed, PDO::PARAM_STR);
                $query->execute();
                $rowCount = $query->rowCount();
                
                if ($rowCount === 0) {
                    $response = Response::initFailure(500,"Failed to create task");
                    $response->send();
                    exit();
                }
                
                $lastTaskID = $writeDB->lastInsertId();
                $query = $writeDB->prepare('select id, title, description, DATE_FORMAT(deadline, "%d/%m/%Y %H:%i") as deadline, completed from tbltasks where id = :taskid');
                $query->bindParam(':taskid', $lastTaskID, PDO::PARAM_INT);
                $query->execute();
                $rowCount = $query->rowCount();
                
                if ($rowCount === 0) {
                    $response = Response::initFailure(500,"Failed to retrieve task");
                    $response->send();
                    exit();
                }
                
                $taskArray = array();
                while($row = $query->fetch(PDO::FETCH_ASSOC)) {
                    $task = new Task($row['id'], $row['title'], $row['description'], $row['deadline'], $row['completed']);
                    $taskArray[] = $task->returnTaskArray();
                }
                
                $returnData = array();
                $returnData['rows_returned'] = $rowCount;
                $returnData['tasks'] = $taskArray;
                
                $response = Response::initSuccess(201,"Task created successfully",$returnData,false);
                $response->send();
                exit();
            } catch (TaskException $ex) {
                $response = Response::initFailure(400,$ex->getMessage());
                $response->send();
                exit();
            } catch (PDOException $ex) {
                error_log("Database query error - ".$ex, 0);
                $response = Response::initFailure(500,"Failed to insert task into database - check submitted data for errors");
                $response->send();
                exit();
            }
            
            
            
            
        } else {
            $response = Response::initFailure(405,"Request method not allowed");
            $response->send();
            exit();
        }
        
        
    } else {
        $response = Response::initFailure(404,"Endpoint not found");
        $response->send();
        exit();
    }
    
    
    ?>
