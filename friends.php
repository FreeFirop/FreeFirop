<?php
include 'db.php';
header("Access-Control-Allow-Origin: *"); // Allow all origins
header("Access-Control-Allow-Methods: GET, POST, OPTIONS"); // Allow these methods
header("Access-Control-Allow-Headers: Content-Type"); // Allow Content-Type header
header("Content-Type: application/json");
if (!$db) {
    echo json_encode(["error" => "Database connection failed"]);
    exit();
}


// Check if action is provided
if (!isset($_GET['action'])) {
    echo json_encode(["error" => "No action specified"]);
    exit();
}

$action = $_GET['action'] ?? '';

switch ($action) {
    case 'send_request':
        sendFriendRequest($db);
        break;
    case 'fetch_requests':
        fetchFriendRequests($db);
        break;
    case 'accept_request':
        acceptFriendRequest($db);
        break;
    case 'decline_request':
        declineFriendRequest($db);
        break;
    case 'fetch_friends':
        fetchFriendsList($db);
        break;
        case 'send_group_invite':
    sendGroupInvite($db);
    break;    
    case 'get_friend_id':
    getFriendId($db);
    break;   
    case 'fetch_group_invites':
    fetchGroupInvites($db);
    break;
    case 'remove_friend':
    removeFriends($db);
    break;
case 'count_friends':  
        countFriends($db);  
        break;
case 'block_friend':  
        blockUser($db);  
        break;
case 'unblock_friend':  
        unblockUser($db);  
        break;
 case 'fetch_blocked_friends':  
        fetchBlockedFriends($db);  
        break;
 case "fetch_friend_about":
        fetchFriendAbout($db);
        break;
    default:
        echo json_encode(["error" => "Invalid action"]);
        exit();
}
// Function to send a friend request
function sendFriendRequest($db) {
    $data = json_decode(file_get_contents("php://input"), true);

    if (!isset($data['sender_id']) || !isset($data['receiver_id'])) {
        echo json_encode(["error" => "Invalid request data"]);
        exit();
    }

    $senderId = (int)$data['sender_id'];
    $receiverId = (int)$data['receiver_id'];

    if ($senderId === $receiverId) {
        echo json_encode(["error" => "You cannot send a friend request to yourself."]);
        exit();
    }

    // ✅ Step 1: Check if they are already friends
    $checkFriendship = $db->prepare("SELECT id FROM friends WHERE 
        (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)");
    $checkFriendship->execute([$senderId, $receiverId, $receiverId, $senderId]);

    if ($checkFriendship->rowCount() > 0) {
        echo json_encode(["error" => "You are already friends."]);
        exit();
    }

    // ✅ Step 2: Check if a request already exists
    $checkRequest = $db->prepare("SELECT id FROM friend_requests WHERE sender_id = ? AND receiver_id = ?");
    $checkRequest->execute([$senderId, $receiverId]);

    if ($checkRequest->rowCount() > 0) {
        echo json_encode(["error" => "Friend request already sent."]);
        exit();
    }

    // ✅ Step 3: Insert Friend Request
    $stmt = $db->prepare("INSERT INTO friend_requests (sender_id, receiver_id) VALUES (?, ?)");
    if ($stmt->execute([$senderId, $receiverId])) {
        echo json_encode(["success" => true, "message" => "Friend request sent"]);
    } else {
        echo json_encode(["error" => "Database error"]);
    }
}

// Function to fetch friend requests sent to the logged-in user
function fetchFriendRequests($db) {
    $data = json_decode(file_get_contents("php://input"), true);

    if (!isset($data['user_id'])) {
        echo json_encode(["success" => false, "message" => "User ID is missing"]);
        exit();
    }

    $receiverId = $data['user_id'];

    try {
        $stmt = $db->prepare("
            SELECT fr.id, u.id AS sender_id, u.username, u.profile_icon
            FROM friend_requests fr
            JOIN users u ON fr.sender_id = u.id
            WHERE fr.receiver_id = ?
            ORDER BY fr.id DESC
        ");
        $stmt->execute([$receiverId]);
        $friendRequests = $stmt->fetchAll(PDO::FETCH_ASSOC);

        echo json_encode(["success" => true, "requests" => $friendRequests]);
    } catch (PDOException $e) {
        echo json_encode(["success" => false, "message" => "Database error: " . $e->getMessage()]);
    }
}

function acceptFriendRequest($db) {
    $data = json_decode(file_get_contents("php://input"), true);
    if (!isset($data['request_id'])) {
        echo json_encode(["success" => false, "message" => "Request ID is missing"]);
        exit();
    }

    $requestId = (int)$data['request_id'];

    // Fetch sender and receiver details
    $stmt = $db->prepare("SELECT sender_id, receiver_id FROM friend_requests WHERE id = ?");
    $stmt->execute([$requestId]);
    $friendRequest = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$friendRequest) {
        echo json_encode(["success" => false, "message" => "Friend request not found"]);
        exit();
    }

    $senderId = $friendRequest['sender_id'];
    $receiverId = $friendRequest['receiver_id'];

    try {
        $db->beginTransaction(); // ✅ Start transaction

        // Check if friendship already exists
        $checkStmt = $db->prepare("SELECT * FROM friends WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)");
        $checkStmt->execute([$senderId, $receiverId, $receiverId, $senderId]);

        if ($checkStmt->rowCount() > 0) {
            echo json_encode(["success" => false, "message" => "Already friends"]);
            $db->rollBack(); // Undo transaction
            exit();
        }

        // Insert into friends table
        $stmt = $db->prepare("INSERT INTO friends (user_id, friend_id) VALUES (?, ?)");
        $stmt->execute([$senderId, $receiverId]);

        // Delete the friend request
        $stmt = $db->prepare("DELETE FROM friend_requests WHERE id = ?");
        $stmt->execute([$requestId]);

        $db->commit(); // ✅ Commit transaction

        echo json_encode(["success" => true, "message" => "Friend request accepted"]);
    } catch (Exception $e) {
        $db->rollBack(); // Undo transaction on error
        echo json_encode(["success" => false, "message" => "Database error: " . $e->getMessage()]);
    }
}

function declineFriendRequest($db) {
    $data = json_decode(file_get_contents("php://input"), true);
    if (!isset($data['request_id'])) {
        echo json_encode(["success" => false, "message" => "Request ID is missing"]);
        exit();
    }

    $requestId = $data['request_id'];

    // Delete friend request
    $stmt = $db->prepare("DELETE FROM friend_requests WHERE id = ?");
    $stmt->execute([$requestId]);

    echo json_encode(["success" => true, "message" => "Friend request declined"]);
}

function fetchFriendsList($db) {
    $data = json_decode(file_get_contents("php://input"), true);
    if (!isset($data['user_id'])) {
        echo json_encode(["success" => false, "message" => "User ID is missing"]);
        exit();
    }

    $userId = $data['user_id'];

    $stmt = $db->prepare("
        SELECT u.id, u.username, u.profile_icon, f.created_at
        FROM friends f
        JOIN users u ON (f.user_id = u.id OR f.friend_id = u.id)
        WHERE (f.user_id = ? OR f.friend_id = ?) AND u.id != ?
    ");
    $stmt->execute([$userId, $userId, $userId]);
    $friends = $stmt->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode(["success" => true, "friends" => $friends]);
}


function sendGroupInvite($db) {
    $data = json_decode(file_get_contents("php://input"), true);

    if (!isset($data['inviter_id']) || !isset($data['group_id']) || !isset($data['invitee_id'])) {
        echo json_encode(["success" => false, "message" => "Missing required fields"]);
        exit();
    }

    $inviterId = (int)$data['inviter_id'];
    $groupId = (int)$data['group_id']; // Use `currentGroupId`
    $inviteeId = (int)$data['invitee_id'];
    
    $checkMemberStmt = $db->prepare("SELECT id FROM group_members WHERE group_id = ? AND user_id = ?");
    $checkMemberStmt->execute([$groupId, $inviteeId]);
    $isMember = $checkMemberStmt->fetch(PDO::FETCH_ASSOC);
    $checkMemberStmt->closeCursor();

    if ($isMember) {
        echo json_encode(["success" => false, "message" => "Your friend is already in this group."]);
        exit();
    }

    // Check if invitee is a friend
    $stmt = $db->prepare("SELECT * FROM friends WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)");
    $stmt->execute([$inviterId, $inviteeId, $inviteeId, $inviterId]);

    if ($stmt->rowCount() === 0) {
        echo json_encode(["success" => false, "message" => "This user is not your friend."]);
        exit();
    }

    // Prevent duplicate invites
    $checkInvite = $db->prepare("SELECT id FROM group_invites WHERE group_id = ? AND inviter_id = ? AND invitee_id = ?");
    $checkInvite->execute([$groupId, $inviterId, $inviteeId]);

    if ($checkInvite->rowCount() > 0) {
        echo json_encode(["success" => false, "message" => "Invitation already sent."]);
        exit();
    }
    // Insert invite
    $stmt = $db->prepare("INSERT INTO group_invites (group_id, inviter_id, invitee_id) VALUES (?, ?, ?)");
    if ($stmt->execute([$groupId, $inviterId, $inviteeId])) {
        echo json_encode(["success" => true, "message" => "Group invite sent!"]);
    } else {
        echo json_encode(["success" => false, "message" => "Failed to send invite."]);
    }
}

function getFriendId($db) {
    $data = json_decode(file_get_contents("php://input"), true);

    if (!isset($data['username'])) {
        echo json_encode(["success" => false, "message" => "Friend username is missing."]);
        exit();
    }

    $friendUsername = $data['username'];

    $stmt = $db->prepare("SELECT id FROM users WHERE username = ?");
    $stmt->execute([$friendUsername]);
    $friend = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$friend) {
        echo json_encode(["success" => false, "message" => "Friend not found."]);
        exit();
    }

    echo json_encode(["success" => true, "friend_id" => $friend['id']]);
}

function fetchGroupInvites($db) {
    $data = json_decode(file_get_contents("php://input"), true);

    if (!isset($data['user_id'])) {
        echo json_encode(["success" => false, "message" => "User ID is missing"]);
        exit();
    }

    $userId = $data['user_id'];

    try {
        $stmt = $db->prepare("
            SELECT 
                gi.id, 
                gi.group_id, 
                g.name AS group_name, 
                g.icon AS group_icon, 
                g.description AS group_description, 
                g.privacy AS group_privacy,
                u.username AS inviter_name,
                u.profile_icon AS inviter_icon
            FROM group_invites gi
            JOIN groups g ON gi.group_id = g.id
            JOIN users u ON gi.inviter_id = u.id
            WHERE gi.invitee_id = ? 
              AND gi.group_id NOT IN (
                  SELECT group_id FROM group_members WHERE user_id = ?
              )
            ORDER BY gi.id DESC
        ");
        $stmt->execute([$userId, $userId]);
        $groupInvites = $stmt->fetchAll(PDO::FETCH_ASSOC);

        echo json_encode(["success" => true, "invites" => $groupInvites]);
        exit();
    } catch (PDOException $e) {
        echo json_encode(["success" => false, "message" => "Database error: " . $e->getMessage()]);
    }
}

function removeFriends($db) {
    $data = json_decode(file_get_contents("php://input"), true);

    if (!isset($data['user_id']) || !isset($data['friend_id'])) {
        echo json_encode(["success" => false, "message" => "Missing required fields"]);
        exit();
    }

    $user_id = (int)$data['user_id'];
    $friend_id = (int)$data['friend_id'];

    try {
        $stmt = $db->prepare("DELETE FROM friends WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)");
        $stmt->execute([$user_id, $friend_id, $friend_id, $user_id]);

        if ($stmt->rowCount() > 0) {
            echo json_encode(["success" => true, "message" => "Friend removed successfully"]);
        } else {
            echo json_encode(["success" => false, "message" => "Friend not found or already removed"]);
        }
    } catch (Exception $e) {
        echo json_encode(["success" => false, "message" => "Error: " . $e->getMessage()]);
    }
}

// Function to count friends
function countFriends($db) {
    if (!isset($_GET['user_id'])) {
        echo json_encode(["error" => "User ID is required"]);
        return;
    }

    $userId = (int)$_GET['user_id'];

    // Get all the user's friends
    $stmt = $db->prepare("
        SELECT friend_id FROM friends WHERE user_id = ?
        UNION 
        SELECT user_id FROM friends WHERE friend_id = ?
    ");
    $stmt->execute([$userId, $userId]);
    $friends = $stmt->fetchAll(PDO::FETCH_COLUMN);

    $friendCounts = [];

    foreach ($friends as $friendId) {
        // Get the number of friends this friend has
        $stmt = $db->prepare("
            SELECT COUNT(*) AS friend_count 
            FROM friends 
            WHERE (user_id = ? OR friend_id = ?) AND user_id != ? AND friend_id != ?
        ");
        $stmt->execute([$friendId, $friendId, $userId, $userId]); // Exclude the logged-in user
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        // Store friend count for each friend
        $friendCounts[$friendId] = $result['friend_count'];
    }

    echo json_encode($friendCounts);
}

function blockUser($db) {
    $data = json_decode(file_get_contents("php://input"), true);

    // ✅ Validate required fields
    if (!isset($data['user_id']) || !isset($data['blocked_user_id'])) {
        echo json_encode(["success" => false, "message" => "Missing required fields (user_id and blocked_user_id)"]);
        exit();
    }

    $user_id = $data['user_id'];  
    $blocked_user_id = $data['blocked_user_id'];  

    try {
        // ✅ Step 1: Check if already blocked
        $checkStmt = $db->prepare("SELECT id FROM blocked_friends WHERE user_id = ? AND blocked_user_id = ?");
        $checkStmt->execute([$user_id, $blocked_user_id]);

        if ($checkStmt->rowCount() > 0) {
            echo json_encode(["success" => false, "message" => "your friend is already blocked"]);
            exit();
        }

        // ✅ Step 2: Insert into blocked_friends table
        $stmt = $db->prepare("INSERT INTO blocked_friends (user_id, blocked_user_id) VALUES (?, ?)");
        $stmt->execute([$user_id, $blocked_user_id]);

        echo json_encode(["success" => true, "message" => "User blocked successfully"]);
    } catch (Exception $e) {
        echo json_encode(["success" => false, "message" => "Database error: " . $e->getMessage()]);
    }
}

function unblockUser($db) {
    $data = json_decode(file_get_contents("php://input"), true);

    // ✅ Validate required fields
    if (!isset($data['user_id']) || !isset($data['blocked_user_id'])) {
        echo json_encode(["success" => false, "message" => "Missing required fields (user_id and blocked_user_id)"]);
        exit();
    }

    $user_id = $data['user_id'];  
    $blocked_user_id = $data['blocked_user_id'];  

    try {
        // ✅ Step 1: Check if the user is actually blocked
        $checkStmt = $db->prepare("SELECT id FROM blocked_friends WHERE user_id = ? AND blocked_user_id = ?");
        $checkStmt->execute([$user_id, $blocked_user_id]);

        if ($checkStmt->rowCount() === 0) {
            echo json_encode(["success" => false, "message" => "User is not blocked"]);
            exit();
        }

        // ✅ Step 2: Delete the blocked user entry
        $stmt = $db->prepare("DELETE FROM blocked_friends WHERE user_id = ? AND blocked_user_id = ?");
        $stmt->execute([$user_id, $blocked_user_id]);

        echo json_encode(["success" => true, "message" => "User unblocked successfully"]);
    } catch (Exception $e) {
        echo json_encode(["success" => false, "message" => "Database error: " . $e->getMessage()]);
    }
}

function fetchBlockedFriends($db) {
    $data = json_decode(file_get_contents('php://input'), true);

    $userId = $data['user_id'] ?? null;

    if (!$userId) {
        echo json_encode(['success' => false, 'message' => 'User ID is required.']);
        return;
    }

    try {
        $stmt = $db->prepare("
            SELECT u.id AS user_id, u.username, u.profile_icon 
            FROM blocked_friends b
            JOIN users u ON b.blocked_user_id = u.id
            WHERE b.user_id = ?
        ");
        $stmt->execute([$userId]);
        $blockedUsers = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // ✅ Always return success: true, even if no blocked users exist
        echo json_encode(['success' => true, 'users' => $blockedUsers]);
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    }
}

function fetchFriendAbout($db) {
    $data = json_decode(file_get_contents("php://input"), true);

    if (!isset($data['friend_id'])) {
        echo json_encode(["success" => false, "message" => "Friend ID is missing"]);
        exit();
    }

    $friendId = $data['friend_id'];

    try {
        $stmt = $db->prepare("SELECT about FROM users WHERE id = ?");
        $stmt->execute([$friendId]);
        $aboutData = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($aboutData) {
            echo json_encode(["success" => true, "about" => $aboutData['about']]);
            exit();
        } else {
            echo json_encode(["success" => false, "message" => "About not found"]);
            exit();
        }
    } catch (PDOException $e) {
        echo json_encode(["success" => false, "message" => "Database error: " . $e->getMessage()]);
        exit();
    }
}
?>