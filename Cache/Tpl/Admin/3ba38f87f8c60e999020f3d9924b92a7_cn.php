<?php if (!defined('Yourphp')) die('Yourphp');?><!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=<?php echo C('DEFAULT_CHARSET');?>" />
<title><?php echo L('welcome');?> - Powered by Yourphp</title>
<script type="text/javascript" src="/Statics/Js/jquery.min.js"></script>
<script language="JavaScript">
<!--
$.YourphpInc([ '/Statics/Js/yourphp.admin.min.js','/Statics/Css/style.css']);
function confirm_delete(url){
	var submit = function (v, h, f) {
		if (v == 'ok'){
			location.href = url;
		}
		return true;
	};
	top.YpBox.confirm("<?php echo L('real_delete');?>", "Message", submit);
}
function selectall(name) {
	if (document.getElementById("check_box").checked) {
		$("input[name='"+name+"']").each(function() {
			this.checked=true;
		});
	} else {
		$("input[name='"+name+"']").each(function() {
			this.checked=false;
		});
	}
}
function Tabs(id,title,content,box,on,action){
	if(action){
		  $(id+' '+title).click(function(){
			  $(this).addClass(on).siblings().removeClass(on);
			  $(content+" > "+box).eq($(id+' '+title).index(this)).show().siblings().hide();
		  });
	  }else{
		  $(id+' '+title).mouseover(function(){
			  $(this).addClass(on).siblings().removeClass(on);
			  $(content+" > "+box).eq($(id+' '+title).index(this)).show().siblings().hide();
		  });
	  }
}

function openwin(id,url,title,width,height,lock,yesdo,topurl){ 

	top.YpBox.open("iframe:"+url,title,width,height,{
			id:id,
			submit: function (v, h, f){
				iframeWin = top.YpBox.getIframe(id);
				if (v == 'ok'){
					if(yesdo || topurl){
						if(yesdo){
							yesdo.call(this,iframeWin, id,inputid); 
						}else{
							top.jBox.close(true);
							top.location.href=topurl;
						}
					}else{
						var form = $(iframeWin).contents().find('#dosubmit');
						$(form).click();
						return false;
					}

				}
			}
		});
 
}

function showpicbox(url){
	top.YpBox( '<img src="'+url+'" />',{width:'auto'});
} 
//-->
</script>
</head>
<body width="100%" style="overflow-x:hidden;">
<div id="loader" ><?php echo L('load_page');?></div>
<div id="result" class="result none"></div>
<div class="mainbox">

<?php if(empty($_GET['isajax'])) { ?>
	<div id="nav" class="mainnav_title">
	<div id="lang">
	<?php if(APP_LANG) { ?>
		<?php
		parse_str($_SERVER['QUERY_STRING'],$urlarr);
		unset($urlarr[l]);
		$url='?'.http_build_query($urlarr);
		?>
		<?php $n=1;if(is_array($Lang)) foreach($Lang AS $langvo) { ?>		 
			<a href="<?php echo $url;?>&l=<?php echo $langvo['mark'];?>" <?php if($langvo[mark]==$_SESSION['YP_lang']) { ?> class="on"<?php } ?>><?php echo $langvo['name'];?></a>
		<?php $n++;}unset($n); ?>
	<?php } ?>
	</div>
	<ul><a href="<?php echo U($nav[bnav][model].'/'.$nav[bnav][action],$nav[bnav][data]);?>"><?php echo $nav['bnav']['name'];?></a>|
	<?php $n=1;if(is_array($nav[nav])) foreach($nav[nav] AS $vonav) { ?>	
	<?php if($vonav[data][isajax]) { ?>
	<a href="javascript:void(0);" onclick="openwin('<?php echo $vonav['action'];?>','<?php echo U($vonav[model].'/'.$vonav[action],$vonav[data]);?>','<?php echo $vonav['name'];?>',600,440)"><?php echo $vonav['name'];?></a>|
	<?php } else { ?>
	<a href="<?php echo U($vonav[model].'/'.$vonav[action],$vonav[data]);?>"><?php echo $vonav['name'];?></a>|
	<?php } ?>
	<?php $n++;}unset($n); ?></ul>
	</div>
	<script>
	//|str_replace=.'/index.php','',###
	var onurl ='<?php echo $_SERVER["REQUEST_URI"];?>';
	jQuery(document).ready(function(){
		$('#nav ul a ').each(function(i){
		if($('#nav ul a').length>1){
			var thisurl= $(this).attr('href');
			thisurl = thisurl.replace('&menuid=<?php echo cookie("menuid");?>','');
			if(onurl.indexOf(thisurl) == 0 ) $(this).addClass('on').siblings().removeClass('on');
		}else{
			$('#nav ul').hide();
		}
		});
		if($('#nav ul a ').hasClass('on')==false){
		$('#nav ul a ').eq(0).addClass('on');
		}
	});
	</script>
<?php } ?>

<script>
 
if(self==top){
	window.top.location.href = '<?php echo U("Login/index");?>';
}</script>

<style>

.mainnav_title{ display:none;}
h1 { height:30px;line-height:30px;font-size:14px;padding-left:15px;background:#EEE;border-bottom:1px solid #ddd;border-right:1px solid #ddd;overflow:hidden;zoom:1;margin-bottom:10px;}
h1 b {color:#3865B8;}
h1 span {color:#ccc;font-size:10px;margin-left:10px;}
#Profile{ width:48%; height:191px; float:left;margin:5px 15px 0 0;}
#system {width:48%;float:left;margin:5px 15px 0 0;}
.list ul{ border:1px #ddd solid;  overflow:hidden;border-bottom:none;}
.list ul li{ border-bottom:1px #ddd solid; height:26px;  overflow:hidden;zoom:1; line-height:26px; color:#777;padding-left:5px;}
.list ul li span{ display:block; float:left; color:#777;width:100px;}

#sitestats {width:48%; height:191px; float:left;margin:5px 0  0 0;overflow:hidden;}
#sitestats div {_width:99.5%;border:1px solid #ddd;overflow:hidden;zoom:1;}
#sitestats ul {overflow:hidden;zoom:1;width:102%;padding:2px 0 0 2px;_padding:1px 0 0 1px;height:132px;}
#sitestats ul li {float:left;height:44px; float:left; width:16.1%;_width:16.3%;text-align:center;border-right:1px solid #fff;border-bottom:none;}
#sitestats ul li b {float:left;width:100%;height:21px;line-height:22px;  background:#EFEFEF;color:#777;font-weight:normal;}
#sitestats ul li span {float:left;width:100%;color:#3865B8;background:#F8F8F8;height:21px;line-height:21px;overflow:hidden;zoom:1;}

#yourphpnews {width:48%;float:left;margin:5px 15px 0 0;}

#tabs {margin:0px auto;overflow:hidden;border:1px solid #ccc; height:214px;}
#tabs .title {overflow:hidden;background:url(/Statics/Images/tab_bottom_line_1.jpg) repeat-x 0 26px;height:27px;}
#tabs .title ul li {float:left;margin-left:-1px;height:26px;line-height:26px;background:#EAEEF4;padding:0px 10px;border:1px solid #ccc;border-top:0;border-bottom:0;}
#tabs .title ul li.on {background:#FFF;height:27px;}
#tabs .content_1 { overflow:hidden;border-top:none;}
#tabs .tabbox {display:none;padding:10px;}

#tabs .tabbox ul li {background:url(/Statics/Images/ico_1.gif) no-repeat 4px 11px;padding-left:13px;border-bottom:1px #ddd dashed; height:27px;  line-height:26px;color:#333 }
#tabs .tabbox ul li a {color:#333}
#tabs .tabbox ul li a:hover {color:#FB0000;}
#tabs .tabbox ul li span.date {float:right;color:#777}
#Yourphp_sn {color:#FB0000;font-weight:normal;}
#Yourphp_license {font-weight:normal;color:blue;}
#Yourphp_license a {color:#FB0000;}
</style>
 
	<div id="Profile" class="list">
		<h1><b><?php echo L(Profile_info);?></b><span>Profile&nbsp; Info</span></h1>
		<ul>

		<?php $n=1; if(is_array($userinfo)) foreach($userinfo AS $key => $v) { ?>
		<li><span><?php echo L($key);?>:</span><?php echo $v;?></li>
		<?php $n++;}unset($n); ?>
		</ul>
	</div>

	<div id="sitestats" >
		<h1><b><?php echo L(Site_Stats);?></b><span>Site&nbsp; Stats</span></h1>
		<div>
		<ul>
		<?php $n=1; if(is_array($moduledata)) foreach($moduledata AS $key => $v) { ?>
		<li><b><?php echo $v['title'];?></b><br><span><?php echo $v['counts'];?></span></li>
		<?php $n++;}unset($n); ?>
		<li><b></b><span></span></li>
		<li><b></b><span></span></li>
		<li><b></b><span></span></li>
		<li><b></b><span></span></li>
		<li><b></b><span></span></li>
		<li><b></b><span></span></li>
		<li><b></b><span></span></li>
		<li><b></b><span></span></li>
		<li><b></b><span></span></li>
		<li><b></b><span></span></li>
		<li><b></b><span></span></li>
		</ul></div>
	</div>


	<div id="system"  class="list">
		<h1><b><?php echo L(system_info);?></b><span>System&nbsp; Info</span></h1>
		<ul>
		<?php $n=1; if(is_array($server_info)) foreach($server_info AS $key => $v) { ?>
		<li><span><?php echo L($key);?>:</span><?php echo $v;?></li>
		<?php $n++;}unset($n); ?>
		</ul>
	</div>


 	<div id="yourphpnews" class="list">


		<h1><b><?php echo L(Help_News);?></b><span>Soft&nbsp;Update</span></h1>
		<ul>
		<?php $n=1; if(is_array($yourphp_info)) foreach($yourphp_info AS $key => $v) { ?>
		<li><span><?php echo L($key);?>:</span><?php echo $v;?></li>
		<?php $n++;}unset($n); ?>
		<li></li><li></li>
		</ul> 
	</div> 
	<script type="text/javascript" src="http://www.yourphp.cn/index.php?m=Js&a=index&type=license&host=<?php echo $_SERVER['SERVER_NAME'];?>&key=<?php echo YP_KEY;?>&ver=<?php echo VERSION;?>&time=<?php echo UPDATETIME;?>"></script>