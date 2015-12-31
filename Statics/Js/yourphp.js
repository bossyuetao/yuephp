
function Tabs(id,title,content,box,on,type,action){
	if(type){
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
	  if(action){
		$(id+' '+title).eq(action).addClass(on).siblings().removeClass(on);
		$(content+" > "+box).eq(action).show().siblings().hide();
	  }else{
		$(id+' '+title).eq(0).addClass(on).siblings().removeClass(on);
		$(content+" > "+box).eq(0).show().siblings().hide();
	  }
}
function setcookie(name,value){   
    var Days = 30;   
    var exp  = new Date();   
    exp.setTime(exp.getTime() + Days*24*60*60*1000);   
    document.cookie = name + "="+ escape (value) + ";expires=" + exp.toGMTString();   
}

function getcookie(name){  
    var arr = document.cookie.match(new RegExp("(^| )"+name+"=([^;]*)(;|$)"));
    if(arr != null){
		name1=unescape(arr[2]);
		var name = name1.replace(/[\',\"]/g,"");	
        return name;   
    }else{   
        return "";   
    }   
}
  
function delcookie(name){   
    var exp = new Date();    
    exp.setTime(exp.getTime() - 1);   
    var cval=getCookie(name);   
    if(cval!=null) document.cookie= name + "="+cval+";expires="+exp.toGMTString();   
}

function showlogin()
{
	var auth = getcookie('YP_auth');
	if(auth != '')
	{
		$('#login_username').html(unescape(getcookie('YP_username')));
		$('#login_div').hide();
		$('#logined_div').show();
	}
	else
	{
		$('#logined_div').hide();
		$('#login_div').show();
	}
}

$(function(){
    showlogin();
});

function resetVerifyCode(){
	var timenow = new Date().getTime();
	document.getElementById('verifyImage').src= YP_APP+'?g=Home&m=Index&a=verify#'+timenow;
}

function donghua(obj){
	  var speed=20;
	  var demoh  =  document.getElementById(obj);
	  var demoh1 =  document.getElementById(obj+'_1');
	  var demoh2 =  document.getElementById(obj+'_2');
	  demoh2.innerHTML=demoh1.innerHTML;
	  function wfdh(){
		  if(demoh2.offsetWidth-demoh.scrollLeft<=0){demoh.scrollLeft-=demoh1.offsetWidth;}
		  if(demoh2.offsetWidth-demoh.scrollLeft>0){demoh.scrollLeft++;}
	  }
	  var MyMarh=setInterval(wfdh,speed);
	  demoh.onmouseover=function() {clearInterval(MyMarh);}
	  demoh.onmouseout=function() {MyMarh=setInterval(wfdh,speed);}
}

function showon(obj,onobj,id){
	$(obj+' '+ onobj).click(function(){
		if($(this).parent().hasClass('on')){
			$(this).parent().removeClass('on');
		}else{
			$(this).parent().addClass('on');
		}
	});
	if(id){
		$('#catlist_'+id).parent().parent().addClass('on');	
	}
}


function changeorder(obj,moduleid,id,doit,ordercall){

	attrs =Array();
	var i=0;
	$('#attrbox').find("[name^=attr]").each(function() {
		attrid=$(this).attr('rel');
		title=$('#name_'+attrid).html();
		val = $(this).val();
		if(val){
			attrs[i] = {'attrid': attrid,'title':title,'val':val};
		}
		i++;
	});

	var objs  =  document.getElementById(obj);
	var datas={'moduleid':moduleid,'id': id,'num':objs.value,'attr':attrs};

	$.ajax({
		type:"POST",
		url:YP_APP+"?m=Order&a=ajax&do="+doit,
		data: datas,
		timeout:"4000",
		dataType:"JSON",
		success: function(data){
			if(data.data==1){
				ordercall.call(this,obj,moduleid,id,doit,data);
			}else{
				alert(doit + ' error'+data.msg);
			}			
		},
		error:function(){
			alert("time out,try it");
		}
	});
}


function area_change(id,level,province,city,area,provinceid,cityid,areaid){
	var datas={'level':level,'provinceid':provinceid,'cityid':cityid,'areaid':areaid};
	$.ajax({
		type:"POST",
		url: YP_APP+"?m=Ajax&a=Area&id="+id,
		data: datas,
		timeout:"4000",
		dataType:"JSON",
		success: function(data){
			if(level==0){
			$('#'+province).html(data.province);
			$('#'+city).html(data.city);
			$('#'+area).html(data.area);
			}else if(level==1){
			$('#'+city).html(data.city);
			$('#'+area).html(data.area);
			}else if(level==2){
				$('#'+area).html(data.area);
			}
		},
		error:function(){
			alert("time out,try it");
		}
	}); 
}

