<?php if (!defined('Yourphp')) die('Yourphp');?>	
<!DOCTYPE>
<html>
<head>
<title><?php echo L('message_title');?> - Powered by Yourphp</title>
<meta http-equiv="Content-Type" content="text/html; charset=<?php echo C('DEFAULT_CHARSET');?>">
<meta http-equiv='Refresh' content='<?php echo $waitSecond;?>;URL=<?php echo $jumpUrl;?>'>
<link rel="stylesheet" type="text/css" href="/Statics/Css/style.css" /> 
</head>
<body>


<div class="showMsg" style="text-align:center">
	<h5><?php echo L('message_title');?></h5>
    <div class="content guery" style="display:inline-block;display:-moz-inline-stack;zoom:1;*display:inline; max-width:280px"><?php echo $message;?> <?php echo $error;?></div>
    <div class="bottom">
	<?php if(!$closeWin) { ?> 
	<?php echo L('msg_system_1');?> <span style="color:blue;font-weight:bold"><?php echo $waitSecond;?></span> <?php echo L('msg_system_2');?> <a href="<?php echo $jumpUrl;?>"><?php echo L('close');?></a> <?php echo L('click_this');?>
	<?php } ?>
	<?php if($closeWin) { ?> 
	<?php echo L('msg_system_1');?> <span style="color:blue;font-weight:bold"><?php echo $waitSecond;?></span> <?php echo L('msg_system_2');?> <a href="<?php echo $jumpUrl;?>"><?php echo L('click_this');?></a> <?php echo L('jump');?>
	<?php } ?>
	</div>
<?php
	if($_POST['isajax']):
?>
<script>
 setTimeout(function () { top.YpBox.close(true); },  1000);
</script>
<?php
	 endif;
?>
<?php if ($script):?>
<script style="text/javascript"><?php echo $script;?></script>
<?php endif;?>

</div>
</body>
</html>