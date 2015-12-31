<?php 
/**
 * 
 * Category(分类)
 *
 * @package      	YOURPHP
 * @author          liuxun QQ:147613338 <web@yourphp.cn>
 * @copyright     	Copyright (c) 2008-2011  (http://www.yourphp.cn)
 * @license         http://www.yourphp.cn/license.txt
 * @version        	YourPHP企业网站管理系统 v2.1 2012-10-08 yourphp.cn $
 */
if(!defined("Yourphp")) exit("Access Denied");
class CategoryAction extends AdminbaseAction
{
    protected $dao,$categorys,$module;
    function _initialize()
    {
        parent::_initialize();
        foreach ((array)$this->module as $rw){
			if($rw['type']==1 && $rw['status']==1)  $data['module'][$rw['id']] = $rw;
        }
		$this->module=$data['module'];
        $this->assign($data);
		unset($data);
        $this->dao = D('Admin/category');
    }

    /**
     * 列表
     *
     */
    public function index()
    {
        if($this->categorys){
			foreach($this->categorys as $r) {
				if($r['module']=='Page'){
					$r['str_manage'] = '<a href="?g=Admin&m=Page&a=edit&id='.$r['id'].'">'.L('edit_page').'</a> | ';
				}elseif($r['module']==''){
					$r['str_manage'] = '';
				}else{
					$r['str_manage'] = '<a href="?g=Admin&m='.$r['module'].'&a=add&catid='.$r['id'].'">'.L('add_content').'</a> | ';
				}
				$r['str_manage'] .= '<a href="'.U('Category/add',array( 'parentid' => $r['id'],'type'=>$r['type'])).'">'.L('add_catname').'</a> | <a href="'.U('Category/edit',array( 'id' => $r['id'],'type'=>$r['type'])).'">'.L('edit').'</a> | <a href="javascript:confirm_delete(\''.U('Category/delete',array( 'id' => $r['id'])).'\')">'.L('delete').'</a> ';
				$r['modulename']=$this->module[$r['moduleid']]['title'] ? $this->module[$r['moduleid']]['title'] : L('Module_url');
				$r['dis'] =  $r['ismenu'] ? '<font color="green">'.L('display_yes').'</font>' : '<font color="red">'.L('display_no').'</font>' ;				
				$array[] = $r;
			}
			$str  = "<tr>
						<td width='40' align='center'><input name='listorders[\$id]' type='text' size='3' value='\$listorder' class='input-text-c'></td>
						<td align='center'>\$id</td>
						<td >\$spacer\$catname &nbsp;</td>
						<td align='center'>\$modulename</td>
						<td align='center'>\$dis</td>
						<td align='center'><a href='\$url' target='_blank'>".L('fangwen')."</a></td>
						<td align='center'>\$str_manage</td>
					</tr>";
			import ( '@.EXT.Tree' );
			$tree = new Tree ($array);
			unset($array);
			$tree->icon = array('&nbsp;&nbsp;&nbsp;'.L('tree_1'),'&nbsp;&nbsp;&nbsp;'.L('tree_2'),'&nbsp;&nbsp;&nbsp;'.L('tree_3'));
			$tree->nbsp = '&nbsp;&nbsp;&nbsp;';
			$categorys = $tree->get_tree(0, $str);
			$this->assign('categorys', $categorys);
		}
        $this->display();
    }

	public function _before_add()
    {
		
		foreach((array)$this->Urlrule as $key =>$r){
			if($r['ishtml'])$Urlrule[$key]=$r;
		}
		$this->assign('Urlrule', $Urlrule);


		$yourphp_auth_key = sysmd5(C('ADMIN_ACCESS').$_SERVER['HTTP_USER_AGENT']);
		$yourphp_auth = authcode('1-1-0-1-jpeg,jpg,png,gif-3-0', 'ENCODE',$yourphp_auth_key);
		$this->assign('yourphp_auth',$yourphp_auth);


		$templates= template_file();
		$this->assign ( 'templates',$templates );

		$parentid =	intval($_GET['parentid']); 
		$vo['ismenu']=1;
		$vo['moduleid'] =$this->categorys[$parentid]['moduleid'];
		$this->assign('vo', $vo);
		foreach($this->categorys as $r) {
			$array[] = $r;
		}
		import ( '@.EXT.Tree' );	
		$str  = "<option value='\$id' \$selected>\$spacer \$catname</option>";
		$tree = new Tree ($array);		 
		$select_categorys = $tree->get_tree(0, $str,$parentid);
		$usergroup=F('Role');
		$this->assign('rlist',$usergroup);
		$this->assign('select_categorys', $select_categorys);
	}

    /**
     * 提交录入
     *
     */
    public function insert()
    {
		
		/*
		if($_POST['parentid']){
			if($_POST['moduleid']!=$this->categorys[$_POST['parentid']]['moduleid']){
				$this->success(L('chose_notop_module'));
			}			
		}
		*/
		if(empty($_POST['urlruleid']) && $_POST['ishtml']) $this->error(L('do_empty'));
		$_POST['readgroup'] = $_POST['readgroup'] ? implode(',',$_POST['readgroup']) : '';
		$_POST['postgroup'] = $_POST['postgroup'] ? implode(',',$_POST['postgroup']) : '';

		$_POST['catdir'] = $_POST['catdir'] ? $_POST['catdir'] : Pinyin($_POST['catname']);

		$_POST['module'] = $this->module[$_POST['moduleid']]['name'] ? $this->module[$_POST['moduleid']]['name'] : '';
		$_POST['moduleid']= intval($_POST['moduleid']);
		if(APP_LANG)$_POST['lang']=LANG_ID;
        if($this->dao->create())
        {
			$id = $this->dao->add();
            if($id)
            {
				if($_POST['module']=='Page'){
					$_POST['id']=$id;
					if(empty($_POST['title']))$_POST['title'] = $_POST['catname'];
					$Page=D('Page');
					if($Page->create()){
						$Page->add();
					}
				}

				if($_POST['aid']) {
					$Attachment =M('Attachment');		
					$aids =  implode(',',$_POST['aid']);
					$data['catid']= $_POST['catid'];
					$data['moduleid']= $_POST['moduleid'];
					$data['status']= '1';
					$Attachment->where("aid in (".$aids.")")->save($data);
				}

				$this->repair();
				savecache('Category');


				if($_POST['ishtml']){
					$this->categorys = F('Category');				
					$cat = $this->categorys[$id];					
					$arrparentid = array_filter(explode(',',$cat['arrparentid'].','.$cat['id']));
					foreach($arrparentid as $catid) {
						if($this->categorys[$catid]['ishtml'])	$this->clisthtml($catid);					
					}
				}
				if($this->sysConfig['HOME_ISHTML']){ $this->create_index();$this->create_index(1);}
				$this->assign ( 'jumpUrl', U(MODULE_NAME.'/index') );
                $this->success(L('add_ok'));
			}else{
			   $this->error(L('add_error'));
			}
        }else{
            $this->error($this->dao->getError());
        }
    }

    /**
     * 编辑
     *
     */
    public function edit()
    {
		$id = intval($_GET['id']);

		foreach((array)$this->Urlrule as $key =>$r){
			if($r['ishtml'])$Urlrule[$key]=$r;
		}
		$this->assign('Urlrule', $Urlrule);

		$yourphp_auth_key = sysmd5(C('ADMIN_ACCESS').$_SERVER['HTTP_USER_AGENT']);
		$yourphp_auth = authcode('1-1-0-1-jpeg,jpg,png,gif-3-0', 'ENCODE',$yourphp_auth_key);
		$this->assign('yourphp_auth',$yourphp_auth);

		$templates= template_file();
		$this->assign ( 'templates',$templates );

        $record = $this->categorys[$id];
		$record['readgroup'] = explode(',',$record['readgroup']);
        if(empty($id) || empty($record)) $this->error(L('do_empty'));

       	$parentid =	intval($record['parentid']);
		import ( '@.EXT.Tree' );		
		$result = $this->categorys;
		foreach($result as $r) {
			//if($r['type']==1) continue;
			$r['selected'] = $r['id'] == $parentid ? 'selected' : '';
			$array[] = $r;
		}
		$str  = "<option value='\$id' \$selected>\$spacer \$catname</option>";
		$tree = new Tree ($array);		 
		$select_categorys = $tree->get_tree(0, $str,$parentid);
		$this->assign('select_categorys', $select_categorys);
        $this->assign('vo', $record);
		$usergroup=F('Role');
		$this->assign('rlist',$usergroup); 
		$this->display ();
		
    }

    /**
     * 提交编辑
     *
     */
    public function update()
    {
		if(empty($_POST['urlruleid']) && $_POST['ishtml']) $this->error(L('do_empty'));
		$_POST['module'] = $this->module[$_POST['moduleid']]['name'];		
		$_POST['readgroup'] = $_POST['readgroup'] ? implode(',',$_POST['readgroup']) : '';
		$_POST['postgroup'] = $_POST['postgroup'] ? implode(',',$_POST['postgroup']) : '';
		$_POST['arrparentid'] = $this->get_arrparentid($_POST['id']);
		if(empty($_POST['listtype']))$_POST['listtype']=0;
		$_POST['catdir'] = $_POST['catdir'] ? $_POST['catdir'] : Pinyin($_POST['catname']);


		if($_POST['type']){
			$_POST['moduleid']=0;
			$_POST['module']='';
		}
		if (false === $this->dao->create ()) {
			$this->error ( $this->dao->getError () );
		}
		if (false !== $this->dao->save ()) {

			if($_POST['aid']) {
					$Attachment =M('Attachment');		
					$aids =  implode(',',$_POST['aid']);
					$data['moduleid']= $_POST['moduleid'];
					$data['catid']= $_POST['id'];
					$data['status']= '1';
					$Attachment->where("aid in (".$aids.")")->save($data);
				}

			if($_POST['chage_all']){
				$data=array();
				$arrchildid = $this->get_arrchildid($_POST['id']);
				$data['urlruleid'] = $_POST['urlruleid'] ? $_POST['urlruleid'] : '0' ;
				$data['presentpoint'] = $_POST['presentpoint'];
				$data['postgroup'] = $_POST['postgroup'] ? $_POST['postgroup'] : '';
				$data['chargepoint'] = $_POST['chargepoint'];
				$data['paytype'] = $_POST['paytype'];
				$data['repeatchargedays'] = $_POST['repeatchargedays'];
				$data['ismenu'] = $_POST['ismenu'];
				$data['ishtml'] = $_POST['ishtml'];
				$data['pagesize'] = $_POST['pagesize'];
				$data['template_list'] = $_POST['template_list'];
				$data['template_show'] = $_POST['template_show'];
				$data['readgroup'] = $_POST['readgroup'] ? $_POST['readgroup'] : '';
				$r = $this->dao->where( ' id in ('.$arrchildid.')')->data($data)->save();
			}
			$this->repair();
			$this->repair();
			savecache('Category');
			if($_POST['ishtml']){
				$cat=$this->categorys[$_POST['id']];
				$arrparentid = array_filter(explode(',',$cat['arrparentid'].','.$cat['id']));
				foreach($arrparentid as $catid) {
					if($this->categorys[$catid]['ishtml'])	$this->clisthtml($catid);					
				}
			}
			if($this->sysConfig['HOME_ISHTML']){ $this->create_index();$this->create_index(1);}
			$this->assign ( 'jumpUrl', U(MODULE_NAME.'/index') );
			$this->success (L('edit_ok'));
		} else {
			$this->success (L('edit_error').': '.$this->dao->getDbError());
		}
 
    }

	public function repair_cache() {
		$this->repair();
		$this->repair();
		savecache('Category');
		$this->assign ( 'jumpUrl', U(MODULE_NAME.'/index') );
		$this->success(L('do_success'));
	}

	public function repair() {
	 
		@set_time_limit(500);
		$this->categorys = $categorys = array();
		if(APP_LANG)$langwhere =  " and lang = ".LANG_ID;
		$categorys = $this->dao->where("parentid=0".$langwhere)->Order('listorder ASC,id ASC')->select();
		$this->set_categorys($categorys);
		if(is_array($this->categorys)) {
			foreach($this->categorys as $id => $cat) {
				//if($id == 0 || $cat['type']==1) continue;
				$this->categorys[$id]['arrparentid'] = $arrparentid = $this->get_arrparentid($id);
				$this->categorys[$id]['arrchildid'] = $arrchildid = $this->get_arrchildid($id);
				$this->categorys[$id]['parentdir'] =	$cat['parentdir'] = $parentdir = $this->get_parentdir($id);
	 
				$child = is_numeric($arrchildid) ? 0 : 1;
				if( $cat['type']==1){
					$url=$cat['url'];
				}else{
					$url =  geturl($cat,'',$this->Urlrule);
					$url = $url[0];
				}
				$this->dao->save(array('url'=>$url,'parentdir'=>$parentdir,'arrparentid'=>$arrparentid,'arrchildid'=>$arrchildid,'child'=>$child,'id'=>$id));
			}
		}
	}

	public function set_categorys($categorys = array()) {
		if (is_array($categorys) && !empty($categorys)) {
			foreach ($categorys as $id => $c) {
				$this->categorys[$c[id]] = $c;	
				if(APP_LANG)$langwhere =  " and lang = ".LANG_ID;
				$r = $this->dao->where("parentid = $c[id]".$langwhere)->Order('listorder ASC,id ASC')->select();
				$this->set_categorys($r);
			}
		}
		return true;
	}

	public function get_parentdir($id) {
		if($this->categorys[$id]['parentid']==0) return '';
		 
		$arrparentid = $this->categorys[$id]['arrparentid'];
		unset($r);
		if ($arrparentid) {
				$arrparentid = explode(',', $arrparentid);
				$arrcatdir = array();
				foreach($arrparentid as $pid) {
					if($pid==0) continue;
					$arrcatdir[] = $this->categorys[$pid]['catdir'];
				}
				return implode('/', $arrcatdir).'/';
		}
	}


	public function get_arrparentid($id, $arrparentid = '') {
		if(!is_array($this->categorys) || !isset($this->categorys[$id])) return false;
		$parentid = $this->categorys[$id]['parentid'];
		$arrparentid = $arrparentid ? $parentid.','.$arrparentid : $parentid;
		if($parentid) {
			$arrparentid = $this->get_arrparentid($parentid, $arrparentid);
		} else {
			$this->categorys[$id]['arrparentid'] = $arrparentid;
		}
		return $arrparentid;
	}

	public function get_arrchildid($id) {
		$arrchildid = $id;
		if(is_array($this->categorys)) {
			foreach($this->categorys as $catid => $cat) {
				if($cat['parentid'] && $id != $catid) {
					$arrparentids = explode(',', $cat['arrparentid']);
					if(in_array($id, $arrparentids)) $arrchildid .= ','.$catid;
				}
			}
		}
		return $arrchildid;
	}

	public function delete() {
		$catid = intval($_GET['id']);
		$module = $this->categorys[$catid]['module'];
		$moduleid =  $this->categorys[$catid]['moduleid'];
		if(!$this->categorys[$catid]){
			 $this->error(L('do_empty'));
		}
		if($this->categorys[$catid]['child']){
			 $this->error(L('category_does_not_allow_delete'));
		}
		if($this->categorys[$catid]['type']==1){
			$this->dao->delete($catid);
			delattach("catid=$catid");
		}elseif($module=='Page'){
			$this->dao->delete($catid);
			M('Page')->delete($catid);
			delattach("moduleid =$moduleid and catid in($catid)");
		}elseif($module=='Feedback' || $module=='Guestbook'){
			$this->dao->delete($catid);
			M($module)->where('1')->delete();
		}else{ 
			$where =  "catid =$catid ";	
			//$arrchildid = $this->categorys[$catid]['arrchildid'];
			$count = M($module)->where($where)->count();
			if($count) $this->error(L('category_does_not_allow_delete'));
			$this->dao->delete($catid);
			//$moduleid = $this->mod[$module];
			delattach(" moduleid =$moduleid and catid=$catid ");			
		}
		$this->repair();
		savecache('Category');
		$this->success(L('do_success'));
	}

	public function checkdcatdir(){
		$name=$_GET['catdir'];
		$id=$_GET['id'];
		$Cat =  F('Cat_'.LANG_NAME);
		if($Cat[$name]) {
			if($id && $Cat[$name]==$id){echo 'true';exit;}
			echo 'false';
		}else{
			echo 'true';
		}
		exit;
	}

}
