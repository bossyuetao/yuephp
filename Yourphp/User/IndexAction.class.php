<?php
/**
 * 
 * User/IndexAction.class.php (前台会员中心模块)
 *
 * @package      	YOURPHP
 * @author          liuxun QQ:147613338 <admin@yourphp.cn>
 * @copyright     	Copyright (c) 2008-2011  (http://www.yourphp.cn)
 * @license         http://www.yourphp.cn/license.txt
 * @version        	YourPHP企业网站管理系统 v2.1 2012-10-08 yourphp.cn $
 */
defined('YOURPHP_PATH') or exit();
class IndexAction extends BaseAction
{

	function _initialize()
    {	
		parent::_initialize();
		if(!$this->_userid){
			$this->assign('jumpUrl',U('User/Login/index'));
			$this->error(L('nologin'));
			exit;
		}
		$this->dao = M('User');
		$user = $this->dao->find($this->_userid);
		$this->assign('vo',$user);
		unset($_POST['status']);
		unset($_POST['groupid']);
		unset($_POST['amount']);
		unset($_POST['point']);
		unset($_POST['email']);
		unset($_POST['username']);
		$_GET =get_safe_replace($_GET);
		$_POST =get_safe_replace($_POST);
    }

    public function index()
    {
        $this->display();
    }
	
	public function profile()
    {	 
		if($_POST['dosubmit']){
			$_POST['id']=$this->_userid;
			if(!$this->dao->create($_POST)) {
				$this->error($this->dao->getError());
			}
			$this->dao->update_time = time();
			$this->dao->last_ip = ip();
			$result	=	$this->dao->save();
			if(false !== $result) {
				$this->success(L('do_success'));
			}else{
				$this->error(L('do_error'));
			}
			exit;
		}
        $this->display();
    }

	public function avatar()
    {	
		
		if($_POST['dosubmit']){
		
			$_POST['id']=$this->_userid;
			if(!$this->dao->create($_POST)) {
				$this->error($this->dao->getError());
			}
			$this->dao->update_time = time();
			$this->dao->last_ip = ip();
			$result	=	$this->dao->save();
			if(false !== $result) {
				if($_POST['aid']){
					foreach($_POST['aid'] as $r){
					$aids[]=intval($r);
				}
				$Attachment =M('Attachment');		
				$aids =  implode(',',$aids);
				$data['userid']= $this->_userid;
				$data['catid']= 0;
				$data['status']= '1';
				$Attachment->where("aid in (".$aids.")")->save($data);
				}

				$this->success(L('do_success'));
			}else{
				$this->error(L('do_error'));
			}
			exit;
		}

		$yourphp_auth_key = sysmd5(C('ADMIN_ACCESS').$_SERVER['HTTP_USER_AGENT']);
		$yourphp_auth = authcode('0-1-0-1-jpeg,jpg,png,gif-0.2-0', 'ENCODE',$yourphp_auth_key);
		$this->assign('yourphp_auth',$yourphp_auth);
        $this->display();
    }

	public function password()
    {
		if($_POST['dosubmit']){

			if(md5($_POST['verify']) != $_SESSION['verify']) {
				$this->error(L('error_verify'));
			}
			if($_POST['password'] != $_POST['repassword']){
				$this->error(L('password_repassword'));
			}
			$map	=	array();
			$map['password']= array('eq',sysmd5($_POST['oldpassword']));
			$map['id']		=	$this->_userid;
			//检查用户
			if(!$this->dao->where($map)->field('id')->find()) {
				$this->error(L('error_oldpassword'));
			}else {
				//$this->dao->email = $_POST['email'];
				$this->dao->id = $this->_userid;
				$this->dao->update_time = time();
				$this->dao->password	=	sysmd5($_POST['password']);
				$r = $this->dao->save();
				$this->assign('jumpUrl',U('User/Index/password'));
				if($r){
					$this->success(L('do_success'));
				}else{
					$this->error(L('do_error'));
				}
			 }
			 exit;
		}
		$this->display();
    }


		/**
		 * 图片裁剪函数，支持指定定点裁剪和方位裁剪两种裁剪模式
		 * @param <string>  $src_file       原图片路径
		 * @param <int>     $new_width      裁剪后图片宽度（当宽度超过原图片宽度时，去原图片宽度）
		 * @param <int>     $new_height     裁剪后图片高度（当宽度超过原图片宽度时，去原图片高度）
		 * @param <int>     $type           裁剪方式，1-方位模式裁剪；0-定点模式裁剪。
		 * @param <int>     $pos            方位模式裁剪时的起始方位（当选定点模式裁剪时，此参数不起作用）
		 *                                      1为顶端居左，2为顶端居中，3为顶端居右； 
		 *                                      4为中部居左，5为中部居中，6为中部居右； 
		 *                                      7为底端居左，8为底端居中，9为底端居右；
		 * @param <int>     $start_x        起始位置X （当选定方位模式裁剪时，此参数不起作用）
		 * @param <int>     $start_y        起始位置Y（当选定方位模式裁剪时，此参数不起作用）
		 * @return <string>                 裁剪图片存储路径
		 */
	public function thumb($src_file, $new_width, $new_height, $type = 1, $pos = 5, $start_x = 0, $start_y = 0) {
			$pathinfo = pathinfo($src_file);
			$dst_file = $pathinfo['dirname'] . '/' . $pathinfo['filename'] .'_'. $new_width . 'x' . $new_height . '.' . $pathinfo['extension'];
			if (!file_exists($dst_file)) {
				if ($new_width < 1 || $new_height < 1) {
					echo "params width or height error !";
					exit();
				}
				if (!file_exists($src_file)) {
					echo $src_file . " is not exists !";
					exit();
				}
				// 图像类型
				$img_type = exif_imagetype($src_file);
				$support_type = array(IMAGETYPE_JPEG, IMAGETYPE_PNG, IMAGETYPE_GIF);
				if (!in_array($img_type, $support_type, true)) {
					echo "只支持jpg、png、gif格式图片裁剪";
					exit();
				}
				/* 载入图像 */
				switch ($img_type) {
					case IMAGETYPE_JPEG :
						$src_img = imagecreatefromjpeg($src_file);
						break;
					case IMAGETYPE_PNG :
						$src_img = imagecreatefrompng($src_file);
						break;
					case IMAGETYPE_GIF :
						$src_img = imagecreatefromgif($src_file);
						break;
					default:
					echo "载入图像错误!";
					exit();
				}
				/* 获取源图片的宽度和高度 */
				$src_width = imagesx($src_img);
				$src_height = imagesy($src_img);
				/* 计算剪切图片的宽度和高度 */
				$mid_width = ($src_width < $new_width) ? $src_width : $new_width;
				$mid_height = ($src_height < $new_height) ? $src_height : $new_height;
				/* 初始化源图片剪切裁剪的起始位置坐标 */
				switch ($pos * $type) {
					case 1://1为顶端居左 
						$start_x = 0;
						$start_y = 0;
						break;
					case 2://2为顶端居中 
						$start_x = ($src_width - $mid_width) / 2;
						$start_y = 0;
						break;
					case 3://3为顶端居右 
						$start_x = $src_width - $mid_width;
						$start_y = 0;
						break;
					case 4://4为中部居左 
						$start_x = 0;
						$start_y = ($src_height - $mid_height) / 2;
						break;
					case 5://5为中部居中 
						$start_x = ($src_width - $mid_width) / 2;
						$start_y = ($src_height - $mid_height) / 2;
						break;
					case 6://6为中部居右 
						$start_x = $src_width - $mid_width;
						$start_y = ($src_height - $mid_height) / 2;
						break;
					case 7://7为底端居左 
						$start_x = 0;
						$start_y = $src_height - $mid_height;
						break;
					case 8://8为底端居中 
						$start_x = ($src_width - $mid_width) / 2;
						$start_y = $src_height - $mid_height;
						break;
					case 9://9为底端居右 
						$start_x = $src_width - $mid_width;
						$start_y = $src_height - $mid_height;
						break;
					default://随机 
						break;
				}
				// 为剪切图像创建背景画板
				$mid_img = imagecreatetruecolor($mid_width, $mid_height);
				//拷贝剪切的图像数据到画板，生成剪切图像
				imagecopy($mid_img, $src_img, 0, 0, $start_x, $start_y, $mid_width, $mid_height);
				// 为裁剪图像创建背景画板
				$new_img = imagecreatetruecolor($new_width, $new_height);
				//拷贝剪切图像到背景画板，并按比例裁剪
				imagecopyresampled($new_img, $mid_img, 0, 0, 0, 0, $new_width, $new_height, $mid_width, $mid_height);

				/* 按格式保存为图片 */
				switch ($img_type) {
					case IMAGETYPE_JPEG :
						imagejpeg($new_img, $dst_file, 100);
						break;
					case IMAGETYPE_PNG :
						imagepng($new_img, $dst_file, 9);
						break;
					case IMAGETYPE_GIF :
						imagegif($new_img, $dst_file, 100);
						break;
					default:
						break;
				}
			}
			return ltrim($dst_file, '.');
		}

}
?>