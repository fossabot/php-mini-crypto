<html>
	<head>
		<meta charset="utf-8">
		<title>Encoder/Decoder</title>
	</head>
	<body>
		<?= 'Your IP: '. $_SERVER['REMOTE_ADDR'] ?>
		<br/>
		<form action="crypto.php" method="POST">
			<h2>Encoder/Decoder</h2>
			<label>Chuỗi cần thao tác:</label><br/>
			<textarea id="txtString" placeholder="Input String" name="txtString" cols="100" rows="10"><?= isset($_POST['txtString']) ? $_POST['txtString'] : "" ?></textarea>
			<br/>
			<label>Security key (chỉ dành cho encrypt/decrypt):</label><br/><br/>
			<input type="text" name="txtEncryptKey" placeholder="Private key" value="<?=isset($_POST['txtEncryptKey']) ? $_POST['txtEncryptKey'] : "" ?>">
			<br/><br/>
			<button type="submit" name="encrypt">ECB Encrypt + Base64Encode + UrlEncode</button>
			<button type="submit" name="decrypt">ECB Decrypt + Base64Decode + UrlDecode</button>
			<button type="submit" name="encryptC">ECB Encrypt Clear</button>
			<button type="submit" name="decryptC">ECB Decrypt Clear</button>
			<button type="submit" name="rc4Encrypt">RC4 Encrypt</button>
			<button type="submit" name="rc4Decrypt">RC4 Decrypt</button>
			<br/><br/>
			<button type="submit" name="base64Encode">Base64 Encode</button>
			<button type="submit" name="base64Decode">Base64 Decode</button>
			<button type="submit" name="jsonDecode">Json Decode</button>
			<button type="submit" name="jsonEncode">Json Encode</button>
			<button type="submit" name="urlEncode">URL Encode</button>
			<button type="submit" name="urlDecode">URL Decode</button>
			<button type="submit" name="md5Hash">MD5 Hash</button>
			<br/><br/>
			<button type="submit" name="createPrivateKey">Create security key</button>
			<br/>
		</form>
	</body>
</html>
<?php 

if(!empty($_POST)){
	$string = $_POST['txtString'];
	$key_seed = $_POST['txtEncryptKey'];
	$action = "";
	
	check_empty($string);
	$time_start = microtime(true);
	if(isset($_POST['urlEncode'])){
		$action = "Url encode:<br/> ";
		$string = urlencode($string);
	}
	
	if(isset($_POST['urlDecode'])){
		$action = "Url decode:<br/> ";
		$string = urldecode($string);
	}
	
	if(isset($_POST['base64Encode'])){
		$action = "Base64 encode:<br/> ";
		$string = base64_encode($string);
	}
	
	if(isset($_POST['base64Decode'])){
		$action = "Base64 decode:<br/> ";
		$string = base64_decode($string);
	}
	
	if(isset($_POST['jsonDecode'])){
		$action = "Json decode:<br/> ";
		$string = json_decode($string, true);
		$string = var_export($string, true);
	}
	
	if(isset($_POST['jsonEncode'])){
		$action = "Json encode:<br/> ";
		$string = json_encode($string);
	}
	
	if(isset($_POST['encrypt'])){
		$action = "Encrypt: urlencode(base64_encode(encrypt(var_clear_data, var_secret_key)))<br/> ";
		$string = urlencode(base64_encode(encrypt($string, $key_seed)));
	}
	
	if(isset($_POST['decrypt'])){
		$action = "Decrypt: decrypt(base64_decode(urldecode(var_encrypted_data)), var_secret_key)<br/> ";
		$string = decrypt(base64_decode(urldecode($string)), $key_seed);
	}
	
	if(isset($_POST['encryptC'])){
		$action = "encrypt: <br/> ";
		$string = encrypt($string, $key_seed);
	}
	
	if(isset($_POST['decryptC'])){
		$action = "decrypt: <br/> ";
		$string = decrypt($string, $key_seed);
	}
	
	if(isset($_POST['rc4Encrypt'])){
		$action = "Rc4 encrypt:<br/> ";
		$string = RC4Encrypt($string, $key_seed);
	}
	
	if(isset($_POST['rc4Decrypt'])){
		$action = "Rc4 decrypt:<br/> ";
		$string = RC4Decrypt($string, $key_seed);
	}
	
	if(isset($_POST['createPrivateKey'])){
		$action = "Private key (create from <b>AccessToken</b>+<b>UserId</b>):<br/> ";
		$string = createPrivateKey($string);
	}
	
	if(isset($_POST['md5Hash'])){
		$action = "MD5 Hash:<br/> ";
		$string = md5($string);
	}
	$time_end = microtime(true);
	$elapsed_time = ($time_end - $time_start);
	echo "<label>{$action}</label><br/>";
	echo "<textarea cols=\"100\" rows=\"10\">{$string}</textarea>";
	echo "<br/><br/>Elapsed time: ".$elapsed_time.' mic-sec<br/>';
}

function rc4($pt, $key){
	$s = array();
	for ($i=0; $i<256; $i++) {
		$s[$i] = $i;
	}
	$j = 0;
	$x;
	for ($i=0; $i<256; $i++) {
		$j = ($j + $s[$i] + ord($key[$i % strlen($key)])) % 256;
		$x = $s[$i];
		$s[$i] = $s[$j];
		$s[$j] = $x;
	}
	$i = 0;
	$j = 0;
	$ct = '';
	$y;
	for ($y=0; $y<strlen($pt); $y++) {
		$i = ($i + 1) % 256;
		$j = ($j + $s[$i]) % 256;
		$x = $s[$i];
		$s[$i] = $s[$j];
		$s[$j] = $x;
		$ct .= $pt[$y] ^ chr($s[($s[$i] + $s[$j]) % 256]);
	}
	return $ct;
}

function RC4Encrypt($string, $key){
	$str = rc4($string, $key);
	return base64_encode($str);
}

function RC4Decrypt($string, $key){
	$binStr = base64_decode($string);
	$str = rc4($binStr, $key);
	return $str;
}

function check_empty($string){
	if(empty($string)){
		echo 'Vui lòng nhập chuỗi trước khi thực hiện';
		die;
	}
}

function encryptC($input, $key_seed){
	$input = trim($input);
	$block = mcrypt_get_block_size('tripledes', 'ecb');
	$len = strlen($input);
	$padding = $block - ($len % $block);
	$input .= str_repeat(chr($padding), $padding); // generate a 24 byte key from the md5 of the seed
	$key = substr(md5($key_seed), 0, 24);
	$iv_size = mcrypt_get_iv_size(MCRYPT_TRIPLEDES, MCRYPT_MODE_ECB);
	$iv = mcrypt_create_iv($iv_size, MCRYPT_RAND); // encrypt
	$encrypted_data = mcrypt_encrypt(MCRYPT_TRIPLEDES, $key, $input, MCRYPT_MODE_ECB, $iv); // clean up output and return base64 encoded
	return base64_encode($encrypted_data); 
}

function encrypt($input, $key_seed){	
	$br = "<br/>";
	
	$input = trim($input);
	echo 'trim($input)'.", input: $input".$br;
	
	$block = mcrypt_get_block_size('tripledes', 'ecb');
	echo 'mcrypt_get_block_size("tripledes", "ecb")'.", block: $block".$br;
	
	$len = strlen($input);
	echo "strlen(input), len: $len".$br;
	
	$padding = $block - ($len % $block);
	echo '$block - ($len % $block)'.", padding: $padding".$br;
	
	$input .= str_repeat(chr($padding), $padding); // generate a 24 byte key from the md5 of the seed
	echo 'str_repeat(chr($padding), $padding)'.", input: $input".$br; 
	
	$key = substr(md5($key_seed), 0, 24);
	echo 'substr(md5($key_seed), 0, 24)'.", key_seed: $key".$br;
	
	$iv_size = mcrypt_get_iv_size(MCRYPT_TRIPLEDES, MCRYPT_MODE_ECB);
	echo 'mcrypt_get_iv_size(MCRYPT_TRIPLEDES, MCRYPT_MODE_ECB)'.", iv_size: $iv_size".$br;
	
	$iv = mcrypt_create_iv($iv_size, MCRYPT_RAND); // encrypt
	echo 'mcrypt_create_iv($iv_size, MCRYPT_RAND)'.", iv: $iv".$br;
	$encrypted_data = mcrypt_encrypt(MCRYPT_TRIPLEDES, $key, $input, MCRYPT_MODE_ECB, $iv); // clean up 
	
	echo 'mcrypt_encrypt(MCRYPT_TRIPLEDES, $key, $input, MCRYPT_MODE_ECB, $iv)'.", iv: $encrypted_data".$br.$br;
	#output and return base64 encoded
	$output = base64_encode($encrypted_data);
	echo 'base64_encode($encrypted_data)'.", output: $output".$br;
	return $output;
}

function decryptC($input, $key_seed){
	$input = base64_decode($input);
	$key = substr(md5($key_seed), 0, 24);
	$text = mcrypt_decrypt(MCRYPT_TRIPLEDES, $key, $input, MCRYPT_MODE_ECB, '12345678');
	$block = mcrypt_get_block_size('tripledes', 'ecb');
	$packing = ord($text{strlen($text) - 1});
	if ($packing and ( $packing < $block)) {
		for ($P = strlen($text) - 1; $P >= strlen($text) - $packing; $P--) {
			if (ord($text{$P}) != $packing) {
				$packing = 0;
			}
		}
	}
	$text = substr($text, 0, strlen($text) - $packing);
	return $text;
}

function decrypt($input, $key_seed){
	$br = "<br/>";
	$input = base64_decode($input);
	echo 'base64_decode($input), input:'. $input.$br ;
	
	$key = substr(md5($key_seed), 0, 24);
	echo 'substr(md5($key_seed), 0, 24), key:'. $key.$br;
	
	$text = mcrypt_decrypt(MCRYPT_TRIPLEDES, $key, $input, MCRYPT_MODE_ECB, '12345678');
	echo 'mcrypt_decrypt(MCRYPT_TRIPLEDES, $key, $input, MCRYPT_MODE_ECB, "12345678"), text:'.$text.$br;
	
	$block = mcrypt_get_block_size('tripledes', 'ecb');
	echo "mcrypt_get_block_size('tripledes', 'ecb'), block:".$block.$br;
	
	$packing = ord($text{strlen($text) - 1});
	echo 'ord($text{strlen($text) - 1}), packing:'.$packing.$br;
	
	if ($packing and ( $packing < $block)) {
		for ($P = strlen($text) - 1; $P >= strlen($text) - $packing; $P--) {
			if (ord($text{$P}) != $packing) {
				$packing = 0;
			}
		}
	}
	
	$text = substr($text, 0, strlen($text) - $packing);
	echo 'substr($text, 0, strlen($text) - $packing), text:'.$text.$br;
	
	return $text;
}

function createPrivateKey($string){
	//String = accessToken + userId
	$base64Str = base64_encode($string);
	$hashStr = md5($base64Str);
	$privateKey = substr($hashStr, 0, 10);
	return $privateKey;
}
?>