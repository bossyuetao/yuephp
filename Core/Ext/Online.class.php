<?php 
class Online extends Yourphp {

   protected $lifeTime='1800' ,$sessionid='' ,$dao;


   public function __construct(&$params='') {
		$this->lifeTime = C('EXPIRE_TIME') ?  C('EXPIRE_TIME') : 1800;

		if(cookie('onlineid')){
			$this->sessionid = cookie('onlineid');
		}else{
			$this->sessionid = substr(MD5(session_id()), 0, 32);
			cookie('onlineid',$this->sessionid,0);
		}
		$this->dao = M('Online');
		$this->write($this->sessionid);
		$this->gc($this->lifeTime);
    }

    public function open($savePath, $sessName) {
       return true; 
    } 

   public function close() { 
	   return $this->gc($this->lifetime);
   } 

   public function read($sessID) { 
	   $r = $this->dao->find($sessID);
		return $r ? $r['data'] : '';
   } 

   public function write($sessID,$sessData='') {
		$ip = ip();
		$username = cookie('username') ? cookie('username') : '';
		$groupid = cookie('groupid') ? intval(cookie('groupid')) : 4;
		$sessiondata = array(
							'sessionid'=>$sessID,
							'userid'=>intval(cookie('userid')),
							'username'=>$username,
							'ip'=>$ip,
							'lastvisit'=>time(),
							'groupid'=> $groupid,
							'data'=> '',
		);
		return $this->dao->add($sessiondata,'',true);
   }

 
   public function destroy($sessID) { 
	   return $this->dao->delete($this->sessionid);
   } 

   public function gc($sessMaxLifeTime) { 
	   $expiretime = time() -$sessMaxLifeTime; 
		$r =  $this->dao->where(" lastvisit < $expiretime")->delete();
		return $r;
   } 

}