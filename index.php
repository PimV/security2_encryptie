<html>
<body>
	<h2>Encrypt R Us!</h2>
	<?php	
	try {
		$db = new PDO('mysql:host=databases.aii.avans.nl;dbname=rmbverla_db', 'rmbverla', 'runescape1');
	} catch(PDOException $ex) {
		echo 'error';
	}	

	$key = pack('H*', "ED1025684BF30B12E92D5122D8A03CB32D2A2DFE55F3044C9D8DBC4FD51A5898");
	$iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
	$iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);

	$currentId = -1;
	$msgLine = "";	
	
	function login($username, $password) {
		global $currentId;
		global $db;
		
		$stmt = $db->prepare("SELECT * FROM rmbverla_db.security2_users WHERE username = :user AND password = :pass");
		$stmt->bindParam(':user', $username);
		$stmt->bindParam(':pass', $password);
		$stmt->execute();

		if ($stmt->rowCount() > 0) {
			$currentId = $stmt->fetch()['id'];
			return true;
		}
		return false;
	}

	function encrypt($message) {
		global $key;
		global $iv;

		$encryptedMessage = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $message, MCRYPT_MODE_CBC, $iv);
		$encryptedMessage  = $iv . $encryptedMessage;
		$message_base64 = base64_encode($encryptedMessage);
		
		return $message_base64;
	}

	function decrypt($message) {
		global $iv_size;
		global $key;

		$enc_message = $message;
		$enc_message_dec = base64_decode($enc_message);
		$iv_dec = substr($enc_message_dec, 0, $iv_size);

		$message_dec = substr($enc_message_dec, $iv_size);
		$message = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $message_dec, MCRYPT_MODE_CBC, $iv_dec);

		return $message;
	}

	function insertMessage($message) {
		global $currentId;
		global $db;
		$stmtInsert = $db->prepare("INSERT INTO rmbverla_db.security2_messages (user_id, message) VALUES (:user_id, :message)");
		$stmtInsert->bindParam(':user_id', $currentId);
		$stmtInsert->bindParam(':message', $message);
		$stmtInsert->execute();
	}

	function insertUser($username, $password) {
		global $currentId;
		global $db;
		$stmtInsertUser = $db->prepare("INSERT INTO rmbverla_db.security2_users (username, password) VALUES (:username, :password)");
		$stmtInsertUser->bindParam(':username', $username);
		$stmtInsertUser->bindParam(':password', $password);
		$stmtInsertUser->execute();
		$currentId = $db->lastInsertId();
	}

	function setMsgLine() {
		global $db;
		global $msgLine;
		global $currentId;
		$stmt2 = $db->prepare("SELECT message FROM rmbverla_db.security2_messages WHERE user_id = :id");
		$stmt2->bindParam(':id', $currentId);
		$stmt2->execute();		
		if($stmt2->rowCount() > 0) {
			$msgLine = "";
			$msgCount = 0;
			while($row = $stmt2->fetch()) {
				$msgCount++;
				$msgLine .= "Message " . $msgCount . "\n";
				$message = decrypt($row['message']);
				$msgLine .= $message . "\n\n";
			}					
		}
	}

	if (isset($_POST['message']) && strlen($_POST['message']) > 0
		&& isset($_POST['username']) && $_POST['username'] !== ''
		&& isset($_POST['password']) && $_POST['password'] !== '') {

		$encryptedMessage = encrypt($_POST['message']);

	if (login($_POST['username'], $_POST['password']) === false) {
		insertUser($_POST['username'], $_POST['password']);
	}

	insertMessage($encryptedMessage);


} else if(isset($_POST['username']) && $_POST['username'] !== ''
	&& isset($_POST['password']) && $_POST['password'] !== '') {
	if (login($_POST['username'], $_POST['password']) === true) {
		setMsgLine();
	}
}



$db = NULL;
?>

<form method="POST">
	<label for="username">Gebruikersnaam: </label>
	<input type="text" name="username" id="username"/></br>
	<label for="password">Wachtwoord: </label>
	<input type="text" name="password" id="password"/></br>
	<label for="message">Geheim bericht: </label>
	<textarea id="message" name="message"><?php if ($msgLine && strlen($msgLine) > 0) echo $msgLine; ?></textarea></br>
	<button type="submit">Verstuur!</button>
</form>	
</body>
</html>