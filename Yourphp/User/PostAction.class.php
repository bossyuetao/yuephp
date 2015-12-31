<?php
/**
 *
 * PostAction.class.php (前台内容管理)
 *
 * @package      	YOURPHP
 * @author          liuxun QQ:147613338 <web@yourphp.cn>
 * @copyright     	Copyright (c) 2008-2011  (http://www.yourphp.cn)
 * @license         http://www.yourphp.cn/license.txt
 * @version        	YourPHP企业网站管理系统 v2.1 2011-03-01 yourphp.cn $
 */
if(!defined("Yourphp")) exit("Access Denied");
class PostAction extends BaseAction
{
    protected  $dao,$fields;
    public function _initialize()
    {
        parent::_initialize();
		
		if(empty($this->Role[$this->_groupid]['allowpost'])){	
			$this->assign('jumpUrl',U('User/Login/index'));		
			$this->error(L('nologin'));
		}
		$this->moduleid=intval($_REQUEST['moduleid']);
		$catid = intval($_REQUEST['catid']);
		
		if(!$this->moduleid && $catid) $this->moduleid = $this->categorys[$catid]['moduleid'];
		if(!in_array($this->_groupid,explode(',',$this->module[$this->moduleid]['postgroup']))) $this->error (L('add_no_postgroup'));
		if(!$this->module[$this->moduleid]['ispost']) $this->error (L('module_no_postgroup'));
		if($this->moduleid){
			$this->assign ('moduleid',$this->moduleid);
			$module =$this->module[$this->moduleid]['name'];
			$this->dao = M($module);
			$fields = F($this->moduleid.'_Field');
			foreach($fields as $key => $res){
				if($res['unpostgroup']) $res['unpostgroup']=explode(',',$res['unpostgroup']);
				if(!in_array($this->_groupid,$res['unpostgroup'])  && $res['status']){
					$res['setup']=string2array($res['setup']);
					$this->fields[$key]=$res;
				}
			}
			unset($fields);
			unset($res);
			$this->assign ('fields',$this->fields);
		}

		import ( '@.EXT.Tree' );
		import ( '@.EXT.Form' );
		//$this->assign('Form', new Form());	
    }

    /**
	 * 列表
	 *
	 */
    public function index()
    {
		if(!$this->_userid){
			$this->assign('jumpUrl',U('User/Login/index'));	
			$this->error(L('nologin'));
		}
	 
		if($this->categorys){
			foreach ($this->categorys as $r){
				if($r['type']==1 || !in_array($this->_groupid, explode(',',$r['postgroup']))) continue;
				if($r['moduleid'] != $this->moduleid || $r['child']){
					$arr= explode(",",$r['arrchildid']);
					$show=0;
					foreach((array)$arr as $rr){
						if($this->categorys[$rr]['moduleid'] ==$this->moduleid) $show=1;
					}
					if(empty($show))continue;
					$r['disabled'] =  $r['child'] ? ' disabled' : '';
				}else{
					$r['disabled'] = '';
				}
				$array[] = $r;
			}
			$str  = "<option value='\$id' \$disabled \$selected>\$spacer \$catname</option>";
			$tree = new Tree ($array);
			$select_categorys = $tree->get_tree(0, $str);
			$this->assign('select_categorys', $select_categorys);
			$this->assign('categorys', $this->categorys);
		}
		$this->assign('posids', F('Posid'));

		$c=A('Adminbase');
		$map['mid'] = array('eq',$this->moduleid);
		$map['userid']=array('eq',$this->_userid);
		if(APP_LANG)$map['lang'] =array('eq',$this->Lang[LANG_NAME][id]);
		

		$this->assign($_GET);

		$data = $c->_list('Content',$map);
		$this->assign ( 'page', $data['page'] );
		$this->assign ( 'list', $data['list'] );

        $this->display ();
    }

	public function add()
    {

		$form=new Form();
		$form->isadmin=0;
		$form->doThumb  = $this->Role[$this->_groupid]['allowattachment'] ? 1 : 0;
		$form->doAttach = $this->Role[$this->_groupid]['allowattachment'] ? 1 : 0;
		$this->assign ( 'form', $form );
		$module = $this->module[$this->moduleid]['name']; 
		$template =  file_exists(TMPL_PATH.'User/'.$this->sysConfig['DEFAULT_THEME'].'/'.$module.'_edit.html') ? $module.':edit' : 'Post:edit';
		$this->display ( $template);
	}


	public function edit()
    {
		if(!$this->_userid){
			$this->assign('jumpUrl',U('User/Login/index'));	
			$this->error(L('nologin'));
		}
		$id = intval($_REQUEST ['id']);		
		$vo = $this->dao->find ( $id );
 		$form=new Form($vo);
		$form->isadmin=0;
		$form->doAttach= $this->Role[$this->_groupid]['allowattachment'] ? 1 : 0;;
		$form->doThumb  = $this->Role[$this->_groupid]['allowattachment'] ? 1 : 0;
		$this->assign ( 'vo', $vo );		
		$this->assign ( 'form', $form );
		$module = $this->module[$this->moduleid]['name']; 
		$template =  file_exists(TMPL_PATH.'User/'.$this->sysConfig['DEFAULT_THEME'].'/'.$module.'_edit.html') ? $module.':edit' : 'Post:edit';
		$this->display ( $template);
	}

    /**
     * 录入
     *
     */
    public function insert()
    {
		$catid =intval($_POST['catid']);
		if(!in_array($this->_groupid,explode(',',$this->categorys[$catid]['postgroup']))) $this->error (L('add_no_postgroup'));
		$c=A('Admin/Content');
		$_POST['ip'] = ip();
		$userid = $this->_userid;
		$username =  $this->_username ?  $this->_username : get_safe_replace($_POST['username']);
		$c->insert($this->module[$this->moduleid]['name'],$this->fields,$userid, $username,$this->_groupid);
    }

	function update()
	{  
		if(!$this->_userid){
			$this->error(L('nologin'));
		}
		$catid =intval($_POST['catid']);
		if(!in_array($this->_groupid,explode(',',$this->categorys[$catid]['postgroup']))) $this->error (L('add_no_postgroup'));

		$c=A('Admin/Content');
		$c->update($this->module[$this->moduleid]['name'],$this->fields);
	}
 

}?>