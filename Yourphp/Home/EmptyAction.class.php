<?php
/**
 * 
 * Empty (空模块)
 *
 * @package      	YOURPHP
 * @author          liuxun QQ:147613338 <admin@yourphp.cn>
 * @copyright     	Copyright (c) 2008-2011  (http://www.yourphp.cn)
 * @license         http://www.yourphp.cn/license.txt
 * @version        	YourPHP企业网站管理系统 v2.1 2011-03-01 yourphp.cn $
 */
if(!defined("Yourphp")) exit("Access Denied");
class EmptyAction extends Action
{	
	public function _empty()
	{
		$a=ACTION_NAME;
		$id =  intval($_REQUEST['id']);
		$m=MODULE_NAME;
		$bae=new BaseAction();
		if(!method_exists($bae,$a)){
			_404('404');
		}
		$bae->$a($id,$m);
	 
	}
}
?>