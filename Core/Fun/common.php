<?php
// +----------------------------------------------------------------------
// | Yourphp [ WE CAN DO IT JUST YOURPHP IT ]
// +----------------------------------------------------------------------
// | Copyright (c) 2006-2012 http://www.yourphp.cn All rights reserved.
// +----------------------------------------------------------------------
// | Author:  liuxun QQ:147613338 <web@yourphp.cn>
// +----------------------------------------------------------------------

/**
 * YourPHP 函数类
 */
function _404(){
	send_http_status(404);
	exit;
}
/**
 * 发送HTTP状态
 * @param integer $code 状态码
 * @return void
 */
function send_http_status($code) {
    static $_status = array(
        200 => 'OK',
        301 => 'Moved Permanently',
        302 => 'Moved Temporarily ',
        400 => 'Bad Request',
        403 => 'Forbidden',
        404 => 'Not Found',
        500 => 'Internal Server Error',
        503 => 'Service Unavailable',
    );
    if(isset($_status[$code])) {
        header('HTTP/1.1 '.$code.' '.$_status[$code]);
        header('Status:'.$code.' '.$_status[$code]);
    }
}

function halt($error) {
    $e = array();
     
	if (!is_array($error)) {
		$trace          = debug_backtrace();
		$e['message']   = $error;
		$e['file']      = $trace[0]['file'];
		$e['class']     = isset($trace[0]['class'])?$trace[0]['class']:'';
		$e['function']  = isset($trace[0]['function'])?$trace[0]['function']:'';
		$e['line']      = $trace[0]['line'];
		$traceInfo      = '';
		$time = date('y-m-d H:i:m');
		foreach ($trace as $t) {
			$traceInfo .= '[' . $time . '] ' . $t['file'] . ' (' . $t['line'] . ') ';
			$traceInfo .= $t['class'] . $t['type'] . $t['function'] . '(';
			$traceInfo .= implode(', ', $t['args']);
			$traceInfo .=')<br/>';
		}
		$e['trace']     = $traceInfo;
	} else {
		$e              = $error;
	}
    include_once(YOURPHP_PATH.'Template/Default/exception.html');
    exit;
}

function redirect($url, $time=0, $msg='') {
    //多行URL地址支持
    $url        = str_replace(array("\n", "\r"), '', $url);
    if (empty($msg))
        $msg    = "系统将在{$time}秒之后自动跳转到{$url}！";
    if (!headers_sent()) {
        // redirect
        if (0 === $time) {
            header('Location: ' . $url);
        } else {
            header("refresh:{$time};url={$url}");
            echo($msg);
        }
        exit();
    } else {
        $str    = "<meta http-equiv='Refresh' content='{$time};URL={$url}'>";
        if ($time != 0)
            $str .= $msg;
        exit($str);
    }
}
function trace($str){
	halt($str);
}
function throw_exception($msg, $type='ThinkException', $code=0) {
	halt($msg);
}

function safe_deal($str) {
		return str_replace(array('/', '.'), '', $str);
}

function F($name, $value='', $path=DATA_PATH) {
    static $_cache  = array();
    $filename       = $path . $name . '.php';
    if ('' !== $value) {
        if (is_null($value)) {
            // 删除缓存
            return false !== strpos($name,'*')?array_map("unlink", glob($filename)):unlink($filename);
        } else {
            // 缓存数据
            $dir            =   dirname($filename);
            // 目录不存在则创建
            if (!is_dir($dir))
                mkdir($dir,0755,true);
            $_cache[$name]  =   $value;
            return file_put_contents($filename, "<?php\treturn " . var_export($value, true) . ";?>");
        }
    }
    if (isset($_cache[$name]))
        return $_cache[$name];
    // 获取缓存数据
    if (is_file($filename)) {
        $value          =   include $filename;
        $_cache[$name]  =   $value;
    } else {
        $value          =   false;
    }
    return $value;
}


function G($start,$end='',$dec=4) {
    static $_info       =   array();
    static $_mem        =   array();
    if(is_float($end)) { // 记录时间
        $_info[$start]  =   $end;
    }elseif(!empty($end)){ // 统计时间和内存使用
        if(!isset($_info[$end])) $_info[$end]       =  microtime(TRUE);
        if(MEMORY_LIMIT_ON && $dec=='m'){
            if(!isset($_mem[$end])) $_mem[$end]     =  memory_get_usage();
            return number_format(($_mem[$end]-$_mem[$start])/1024);          
        }else{
            return number_format(($_info[$end]-$_info[$start]),$dec);
        }       
            
    }else{ // 记录时间和内存使用
        $_info[$start]  =  microtime(TRUE);
        if(MEMORY_LIMIT_ON) $_mem[$start]           =  memory_get_usage();
    }
}

function N($key, $step=0,$save=false) {
    static $_num    = array();
    if (!isset($_num[$key])) {
        $_num[$key] = (false !== $save)? S('N_'.$key) :  0;
    }
    if (empty($step))
        return $_num[$key];
    else
        $_num[$key] = $_num[$key] + (int) $step;
    if(false !== $save){ // 保存结果
        S('N_'.$key,$_num[$key],$save);
    }
}

/**
 * D函数用于实例化Model 格式 项目://分组/模块
 * @param string $name Model资源地址
 * @param string $layer 业务层名称
 * @return Model
 */
function D($name='',$layer='') {
    if(empty($name)) return new Model;
    static $_model  =   array();
    $layer          =   $layer?$layer: 'Model';
    if(strpos($name,'://')) {// 指定项目
        $name       =   str_replace('://','/'.$layer.'/',$name);
    }else{
        $name       =   C('DEFAULT_APP').'/'.$layer.'/'.$name;
    }
    if(isset($_model[$name]))   return $_model[$name];
    import($name.$layer);
    $class          =   basename($name.$layer);
    if(class_exists($class)) {
        $model      =   new $class();
    }else {
        $model      =   new Model(basename($name));
    }
    $_model[$name]  =  $model;
    return $model;
}

/**
 * M函数用于实例化一个没有模型文件的Model
 * @param string $name Model名称 支持指定基础模型 例如 MongoModel:User
 * @param string $tablePrefix 表前缀
 * @param mixed $connection 数据库连接信息
 * @return Model
 */
function M($name='', $tablePrefix='',$connection='') {
    static $_model  = array();
    if(strpos($name,':')) {
        list($class,$name)    =  explode(':',$name);
    }else{
        $class      =   'Model';
    }
    $guid           =   $tablePrefix . $name . '_' . $class;
    if (!isset($_model[$guid]))
        $_model[$guid] = new $class($name,$tablePrefix,$connection);
    return $_model[$guid];
}

/**
 * A函数用于实例化Action 格式：[项目://][分组/]模块
 * @param string $name Action资源地址
 * @param string $layer 控制层名称
 * @param boolean $common 是否公共目录
 * @return Action|false
 */
function A($name,$layer='',$common=false) {
    static $_action = array();
    $layer      =   $layer?$layer: 'Action';
    $name   =  '@/'.$name;

    if(isset($_action[$name]))  return $_action[$name];
    import($name.$layer);
    $class      =   basename($name.$layer);
    if(class_exists($class,false)) {
        $action             = new $class();
        $_action[$name]     =  $action;
        return $action;
    }else {
        return false;
    }
}

/**
 * 远程调用模块的操作方法 URL 参数格式 [项目://][分组/]模块/操作
 * @param string $url 调用地址
 * @param string|array $vars 调用参数 支持字符串和数组 
 * @param string $layer 要调用的控制层名称
 * @return mixed
 */
function R($url,$vars=array(),$layer='') {
    $info   =   pathinfo($url);
    $action =   $info['basename'];
    $module =   $info['dirname'];
    $class  =   A($module,$layer);
    if($class){
        if(is_string($vars)) {
            parse_str($vars,$vars);
        }
        return call_user_func_array(array(&$class,$action.C('ACTION_SUFFIX')),$vars);
    }else{
        return false;
    }
}

/**
 * 获取和设置语言定义(不区分大小写)
 * @param string|array $name 语言变量
 * @param string $value 语言值
 * @return mixed
 */
function L($name=null, $value=null) {
    static $_lang = array();
    // 空参数返回所有定义
    if (empty($name))
        return $_lang;
    // 判断语言获取(或设置)
    // 若不存在,直接返回全大写$name
    if (is_string($name)) {
        $name = strtoupper($name);
        if (is_null($value))
            return isset($_lang[$name]) ? $_lang[$name] : $name;
        $_lang[$name] = $value; // 语言定义
        return;
    }
    // 批量定义
    if (is_array($name))
        $_lang = array_merge($_lang, array_change_key_case($name, CASE_UPPER));
    return;
}

/**
 * 获取和设置配置参数 支持批量定义
 * @param string|array $name 配置变量
 * @param mixed $value 配置值
 * @return mixed
 */
function C($name=null, $value=null) {
    static $_config = array();
    // 无参数时获取所有
    if (empty($name)) {
        if(!empty($value) && $array = S('c_'.$value)) {
            $_config = array_merge($_config, array_change_key_case($array));
        }
        return $_config;
    }
    // 优先执行设置获取或赋值
    if (is_string($name)) {
        if (!strpos($name, '.')) {
            $name = strtolower($name);
            if (is_null($value))
                return isset($_config[$name]) ? $_config[$name] : null;
            $_config[$name] = $value;
            return;
        }
        // 二维数组设置和获取支持
        $name = explode('.', $name);
        $name[0]   =  strtolower($name[0]);
        if (is_null($value))
            return isset($_config[$name[0]][$name[1]]) ? $_config[$name[0]][$name[1]] : null;
        $_config[$name[0]][$name[1]] = $value;
        return;
    }
    // 批量设置
    if (is_array($name)){
        $_config = array_merge($_config, array_change_key_case($name));
        if(!empty($value)) {// 保存配置值
            S('c_'.$value,$_config);
        }
        return;
    }
    return null; // 避免非法参数
}



/**
 * 导入所需的类库 同java的Import 本函数有缓存功能
 * @param string $class 类库命名空间字符串
 * @param string $baseUrl 起始路径
 * @param string $ext 导入的文件扩展名
 * @return boolean
 */
function import($class, $baseUrl = '', $ext='.class.php') {
    static $_file = array();

    if (isset($_file[$class . $baseUrl]))
        return true;
    else
        $_file[$class . $baseUrl] = true;
    $class_strut     = explode('/', $class);
    if (empty($baseUrl)) {
        $libPath    =   YOURPHP_PATH.'Yourphp/';
        if(substr($class, 0, 6)=='@.EXT.'){
			 //加载内核扩展库
			$baseUrl =YOURPHP_CORE.'Ext/';
			$class = str_replace('@.EXT.','',$class);
			$class = str_replace('.','/',$class);
		}elseif ('@' == $class_strut[0]) {
            $baseUrl = dirname($libPath);
            $class   = substr_replace($class, basename($libPath).'/', 0, strlen($class_strut[0]) + 1);
        }
    }
    if (substr($baseUrl, -1) != '/')
        $baseUrl    .= '/';
    $classfile       = $baseUrl . $class . $ext;
    if (!class_exists(basename($class),false)) {
        // 如果类不存在 则导入类库文件
        return require_cache($classfile);
    }
}

/**
 * 字符串命名风格转换
 * type 0 将Java风格转换为C的风格 1 将C风格转换为Java的风格
 * @param string $name 字符串
 * @param integer $type 转换类型
 * @return string
 */
function parse_name($name, $type=0) {
    if ($type) {
        return ucfirst(preg_replace("/_([a-zA-Z])/e", "strtoupper('\\1')", $name));
    } else {
        return strtolower(trim(preg_replace("/[A-Z]/", "_\\0", $name), "_"));
    }
}

/**
 * 优化的require_once
 * @param string $filename 文件地址
 * @return boolean
 */
function require_cache($filename) {
    static $_importFiles = array();
    if (!isset($_importFiles[$filename])) {
		
        if (file_exists_case($filename)) {
            require $filename;
            $_importFiles[$filename] = true;
        } else {
            $_importFiles[$filename] = false;
        }
    }
    return $_importFiles[$filename];
}



/**
 * 区分大小写的文件存在判断
 * @param string $filename 文件地址
 * @return boolean
 */
function file_exists_case($filename) {
    if (is_file($filename)) {
        if (strstr(PHP_OS, 'WIN') && C('APP_FILE_CASE')) {
            if (basename(realpath($filename)) != basename($filename))
                return false;
        }
        return true;
    }
    return false;
}

/**
 * 去除代码中的空白和注释
 * @param string $content 代码内容
 * @return string
 */
function strip_whitespace($content) {
    $stripStr   = '';
    //分析php源码
    $tokens     = token_get_all($content);
    $last_space = false;
    for ($i = 0, $j = count($tokens); $i < $j; $i++) {
        if (is_string($tokens[$i])) {
            $last_space = false;
            $stripStr  .= $tokens[$i];
        } else {
            switch ($tokens[$i][0]) {
                //过滤各种PHP注释
                case T_COMMENT:
                case T_DOC_COMMENT:
                    break;
                //过滤空格
                case T_WHITESPACE:
                    if (!$last_space) {
                        $stripStr  .= ' ';
                        $last_space = true;
                    }
                    break;
                default:
                    $last_space = false;
                    $stripStr  .= $tokens[$i][1];
            }
        }
    }
    return str_replace(PHP_EOL, '', $stripStr);
}

/**
 * URL组装 支持不同URL模式
 * @param string $url URL表达式，格式：'[分组/模块/操作#锚点@域名]?参数1=值1&参数2=值2...'
 * @param string|array $vars 传入的参数，支持数组和字符串
 * @param string $suffix 伪静态后缀，默认为true表示获取配置值
 * @param boolean $redirect 是否跳转，如果设置为true则表示跳转到该URL地址
 * @param boolean $domain 是否显示域名
 * @return string
 */
function U($url='',$vars='',$suffix=true,$redirect=false,$domain=false) {
    // 解析URL
    $info   =  parse_url($url);
    $url    =  !empty($info['path'])?$info['path']:ACTION_NAME;
    if(isset($info['fragment'])) { // 解析锚点
        $anchor =   $info['fragment'];
        if(false !== strpos($anchor,'?')) { // 解析参数
            list($anchor,$info['query']) = explode('?',$anchor,2);
        }        
        if(false !== strpos($anchor,'@')) { // 解析域名
            list($anchor,$host)    =   explode('@',$anchor, 2);
        }
    }elseif(false !== strpos($url,'@')) { // 解析域名
        list($url,$host)    =   explode('@',$info['path'], 2);
    }
    // 解析子域名
    if(isset($host)) {
        $domain = $host.(strpos($host,'.')?'':strstr($_SERVER['HTTP_HOST'],'.'));
    }elseif($domain===true){
        $domain = $_SERVER['HTTP_HOST'];
        if(C('APP_SUB_DOMAIN_DEPLOY') ) { // 开启子域名部署
            $domain = $domain=='localhost'?'localhost':'www'.strstr($_SERVER['HTTP_HOST'],'.');
            // '子域名'=>array('项目[/分组]');
            foreach (C('APP_SUB_DOMAIN_RULES') as $key => $rule) {
                if(false === strpos($key,'*') && 0=== strpos($url,$rule[0])) {
                    $domain = $key.strstr($domain,'.'); // 生成对应子域名
                    $url    =  substr_replace($url,'',0,strlen($rule[0]));
                    break;
                }
            }
        }
    }

    // 解析参数
    if(is_string($vars)) { // aaa=1&bbb=2 转换成数组
        parse_str($vars,$vars);
    }elseif(!is_array($vars)){
        $vars = array();
    }
    if(isset($info['query'])) { // 解析地址里面参数 合并到vars
        parse_str($info['query'],$params);
        $vars = array_merge($params,$vars);
    }
    
    // URL组装
    $depr = C('URL_PATHINFO_DEPR');
    if($url) {
        if(0=== strpos($url,'/')) {// 定义路由
            $route      =   true;
            $url        =   substr($url,1);
            if('/' != $depr) {
                $url    =   str_replace('/',$depr,$url);
            }
        }else{
            if('/' != $depr) { // 安全替换
                $url    =   str_replace('/',$depr,$url);
            }
            // 解析分组、模块和操作
            $url        =   trim($url,$depr);
            $path       =   explode($depr,$url);
            $var        =   array();
            $var[C('VAR_ACTION')]       =   !empty($path)?array_pop($path):ACTION_NAME;
            $var[C('VAR_MODULE')]       =   !empty($path)?array_pop($path):MODULE_NAME;
            if($maps = C('URL_ACTION_MAP')) {
                if(isset($maps[strtolower($var[C('VAR_MODULE')])])) {
                    $maps    =   $maps[strtolower($var[C('VAR_MODULE')])];
                    if($action = array_search(strtolower($var[C('VAR_ACTION')]),$maps)){
                        $var[C('VAR_ACTION')] = $action;
                    }
                }
            }
            if($maps = C('URL_MODULE_MAP')) {
                if($module = array_search(strtolower($var[C('VAR_MODULE')]),$maps)){
                    $var[C('VAR_MODULE')] = $module;
                }
            }            
            if(C('URL_CASE_INSENSITIVE')) {
                $var[C('VAR_MODULE')]   =   parse_name($var[C('VAR_MODULE')]);
            }
            if(!C('APP_SUB_DOMAIN_DEPLOY') && C('APP_GROUP_LIST')) {
                if(!empty($path)) {
                    $group                  =   array_pop($path);
                    $var[C('VAR_GROUP')]    =   $group;
                }else{
                    if(GROUP_NAME != C('DEFAULT_GROUP')) {
                        $var[C('VAR_GROUP')]=   GROUP_NAME;
                    }
                }
                if(C('URL_CASE_INSENSITIVE') && isset($var[C('VAR_GROUP')])) {
                    $var[C('VAR_GROUP')]    =  strtolower($var[C('VAR_GROUP')]);
                }
            }
        }
    }

	if($var['g']=='Admin'){
		unset($var['g']);$APP=YP_APP;
	}ELSEIF($var['g']=='Home'){
		$APP=YP_PATH.'/index.php';
	}else{
		$APP=YP_APP;
	}

    if(C('URL_MODEL') == 0) { // 普通模式URL转换
        $url        =   $APP.'?'.http_build_query(array_reverse($var));
        if(!empty($vars)) {
            $vars   =   urldecode(http_build_query($vars));
            $url   .=   '&'.$vars;
        }
    }else{ // PATHINFO模式或者兼容URL模式
        if(isset($route)) {
            $url    =   $APP.'/'.rtrim($url,$depr);
        }else{
            $url    =   $APP.'/'.implode($depr,array_reverse($var));
        }
        if(!empty($vars)) { // 添加参数
            foreach ($vars as $var => $val){
                if('' !== trim($val))   $url .= $depr . $var . $depr . urlencode($val);
            }                
        }
        if($suffix) {
            $suffix   =  $suffix===true?C('URL_HTML_SUFFIX'):$suffix;
            if($pos = strpos($suffix, '|')){
                $suffix = substr($suffix, 0, $pos);
            }
            if($suffix && '/' != substr($url,-1)){
                $url  .=  '.'.ltrim($suffix,'.');
            }
        }
    }
    if(isset($anchor)){
        $url  .= '#'.$anchor;
    }
	$url = str_replace('amp;','',$url);
    if($domain) {
        $url   =  (is_ssl()?'https://':'http://').$domain.$url;
    }
    if($redirect) // 直接跳转URL
        redirect($url);
    else
        return $url;
}


/**
 * 缓存管理
 * @param mixed $name 缓存名称，如果为数组表示进行缓存设置
 * @param mixed $value 缓存值
 * @param mixed $options 缓存参数
 * @return mixed
 */
function S($name,$value='',$options=null) {
    static $cache   =   '';
    if(is_array($options)){
        // 缓存操作的同时初始化
        $type       =   isset($options['type'])?$options['type']:'';
        $cache      =   Cache::getInstance($type,$options);
    }elseif(is_array($name)) { // 缓存初始化
        $type       =   isset($name['type'])?$name['type']:'';
        $cache      =   Cache::getInstance($type,$name);
        return $cache;
    }elseif(empty($cache)) { // 自动初始化
        $cache      =   Cache::getInstance();
    }
    if(''=== $value){ // 获取缓存
        return $cache->get($name);
    }elseif(is_null($value)) { // 删除缓存
        return $cache->rm($name);
    }else { // 缓存数据
        $expire     =   is_numeric($options)?$options:NULL;
        return $cache->set($name, $value, $expire);
    }
}

/**
 * 取得对象实例 支持调用类的静态方法
 * @param string $name 类名
 * @param string $method 方法名，如果为空则返回实例化对象
 * @param array $args 调用参数
 * @return object
 */
function get_instance_of($name, $method='', $args=array()) {
    static $_instance = array();
    $identify = empty($args) ? $name . $method : $name . $method . to_guid_string($args);
    if (!isset($_instance[$identify])) {
        if (class_exists($name)) {
            $o = new $name();
            if (method_exists($o, $method)) {
                if (!empty($args)) {
                    $_instance[$identify] = call_user_func_array(array(&$o, $method), $args);
                } else {
                    $_instance[$identify] = $o->$method();
                }
            }
            else
                $_instance[$identify] = $o;
        }
        else
            halt(L('_CLASS_NOT_EXIST_') . ':' . $name);
    }
    return $_instance[$identify];
}

/**
 * 根据PHP各种类型变量生成唯一标识号
 * @param mixed $mix 变量
 * @return string
 */
function to_guid_string($mix) {
    if (is_object($mix) && function_exists('spl_object_hash')) {
        return spl_object_hash($mix);
    } elseif (is_resource($mix)) {
        $mix = get_resource_type($mix) . strval($mix);
    } else {
        $mix = serialize($mix);
    }
    return md5($mix);
}

/**
 * XML编码
 * @param mixed $data 数据
 * @param string $encoding 数据编码
 * @param string $root 根节点名
 * @return string
 */
function xml_encode($data, $encoding='utf-8', $root='Yourphp') {
    $xml    = '<?xml version="1.0" encoding="' . $encoding . '"?>';
    $xml   .= '<' . $root . '>';
    $xml   .= data_to_xml($data);
    $xml   .= '</' . $root . '>';
    return $xml;
}

/**
 * 数据XML编码
 * @param mixed $data 数据
 * @return string
 */
function data_to_xml($data) {
    $xml = '';
    foreach ($data as $key => $val) {
        is_numeric($key) && $key = "item id=\"$key\"";
        $xml    .=  "<$key>";
        $xml    .=  ( is_array($val) || is_object($val)) ? data_to_xml($val) : $val;
        list($key, ) = explode(' ', $key);
        $xml    .=  "</$key>";
    }
    return $xml;
}

/**
 * session管理函数
 * @param string|array $name session名称 如果为数组则表示进行session设置
 * @param mixed $value session值
 * @return mixed
 */
function session($name,$value='') {
    $prefix   =  C('SESSION_PREFIX');
    if(is_array($name)) { // session初始化 在session_start 之前调用
        if(isset($name['prefix'])) C('SESSION_PREFIX',$name['prefix']);
        if(C('VAR_SESSION_ID') && isset($_REQUEST[C('VAR_SESSION_ID')])){
            session_id($_REQUEST[C('VAR_SESSION_ID')]);
        }elseif(isset($name['id'])) {
            session_id($name['id']);
        }
        ini_set('session.auto_start', 0);
        if(isset($name['name']))            session_name($name['name']);
        if(isset($name['path']))            session_save_path($name['path']);
        if(isset($name['domain']))          ini_set('session.cookie_domain', $name['domain']);
        if(isset($name['expire']))          ini_set('session.gc_maxlifetime', $name['expire']);
        if(isset($name['use_trans_sid']))   ini_set('session.use_trans_sid', $name['use_trans_sid']?1:0);
        if(isset($name['use_cookies']))     ini_set('session.use_cookies', $name['use_cookies']?1:0);
        if(isset($name['cache_limiter']))   session_cache_limiter($name['cache_limiter']);
        if(isset($name['cache_expire']))    session_cache_expire($name['cache_expire']);
        if(isset($name['type']))            C('SESSION_TYPE',$name['type']);
        // 启动session
        if(C('SESSION_AUTO_START'))  session_start();
    }elseif('' === $value){ 
        if(0===strpos($name,'[')) { // session 操作
            if('[pause]'==$name){ // 暂停session
                session_write_close();
            }elseif('[start]'==$name){ // 启动session
                session_start();
            }elseif('[destroy]'==$name){ // 销毁session
                $_SESSION =  array();
                session_unset();
                session_destroy();
            }elseif('[regenerate]'==$name){ // 重新生成id
                session_regenerate_id();
            }
        }elseif(0===strpos($name,'?')){ // 检查session
            $name   =  substr($name,1);
            if($prefix) {
                return isset($_SESSION[$prefix][$name]);
            }else{
                return isset($_SESSION[$name]);
            }
        }elseif(is_null($name)){ // 清空session
            if($prefix) {
                unset($_SESSION[$prefix]);
            }else{
                $_SESSION = array();
            }
        }elseif($prefix){ // 获取session
            return isset($_SESSION[$prefix][$name])?$_SESSION[$prefix][$name]:null;
        }else{
            return isset($_SESSION[$name])?$_SESSION[$name]:null;
        }
    }elseif(is_null($value)){ // 删除session
        if($prefix){
            unset($_SESSION[$prefix][$name]);
        }else{
            unset($_SESSION[$name]);
        }
    }else{ // 设置session
        if($prefix){
            if (!is_array($_SESSION[$prefix])) {
                $_SESSION[$prefix] = array();
            }
            $_SESSION[$prefix][$name]   =  $value;
        }else{
            $_SESSION[$name]  =  $value;
        }
    }
}

/**
 * Cookie 设置、获取、删除
 * @param string $name cookie名称
 * @param mixed $value cookie值
 * @param mixed $options cookie参数
 * @return mixed
 */
function cookie($name, $value='', $option=null) {
    // 默认设置
    $config = array(
        'prefix'    =>  C('COOKIE_PREFIX'), // cookie 名称前缀
        'expire'    =>  C('COOKIE_EXPIRE'), // cookie 保存时间
        'path'      =>  C('COOKIE_PATH'), // cookie 保存路径
        'domain'    =>  C('COOKIE_DOMAIN'), // cookie 有效域名
    );
    // 参数设置(会覆盖黙认设置)
    if (!is_null($option)) {
        if (is_numeric($option))
            $option = array('expire' => $option);
        elseif (is_string($option))
            parse_str($option, $option);
        $config     = array_merge($config, array_change_key_case($option));
    }
    // 清除指定前缀的所有cookie
    if (is_null($name)) {
        if (empty($_COOKIE))
            return;
        // 要删除的cookie前缀，不指定则删除config设置的指定前缀
        $prefix = empty($value) ? $config['prefix'] : $value;
        if (!empty($prefix)) {// 如果前缀为空字符串将不作处理直接返回
            foreach ($_COOKIE as $key => $val) {
                if (0 === stripos($key, $prefix)) {
                    setcookie($key, '', time() - 3600, $config['path'], $config['domain']);
                    unset($_COOKIE[$key]);
                }
            }
        }
        return;
    }
    $name = $config['prefix'] . $name;
    if ('' === $value) {
        if(isset($_COOKIE[$name])){
            $value =    $_COOKIE[$name];
            if(0===strpos($value,'think:')){
                $value  =   substr($value,6);
                return array_map('urldecode',json_decode(MAGIC_QUOTES_GPC?get_safe_replace(stripslashes($value)):$value,true));
            }else{
                return $value;
            }
        }else{
            return null;
        }
    } else {
        if (is_null($value)) {
            setcookie($name, '', time() - 3600, $config['path'], $config['domain']);
            unset($_COOKIE[$name]); // 删除指定cookie
        } else {
            // 设置cookie
            if(is_array($value)){
                $value  = 'think:'.json_encode(array_map('urlencode',$value));
            }
            $expire = !empty($config['expire']) ? time() + intval($config['expire']) : 0;
            setcookie($name, $value, $expire, $config['path'], $config['domain']);
            $_COOKIE[$name] = $value;
        }
    }
}

function ip($type = 0) {
	$type       =  $type ? 1 : 0;
    static $ip  =   NULL;
    if ($ip !== NULL) return $ip[$type];
    if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $arr    =   explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $pos    =   array_search('unknown',$arr);
        if(false !== $pos) unset($arr[$pos]);
        $ip     =   trim($arr[0]);
    }elseif (isset($_SERVER['HTTP_CLIENT_IP'])) {
        $ip     =   $_SERVER['HTTP_CLIENT_IP'];
    }elseif (isset($_SERVER['REMOTE_ADDR'])) {
        $ip     =   $_SERVER['REMOTE_ADDR'];
    }
    // IP地址合法验证
    $long = sprintf("%u",ip2long($ip));
    $ip   = $long ? array($ip, $long) : array('0.0.0.0', 0);
    return $ip[$type];
}

// 过滤表单中的表达式
function filter_exp(&$value){
    if (in_array(strtolower($value),array('exp','or'))){
        $value .= ' ';
    }
}

/*user*/
function showTime() {
        // 显示运行时间
        G('beginTime',$GLOBALS['_beginTime']);
        G('viewEndTime');
        $showTime   =   'Process: '.G('beginTime','viewEndTime').' second(s), ';
   
            // 显示详细运行时间
           // $showTime .= '( Load:'.G('beginTime','loadTime').'s Init:'.G('loadTime','initTime').'s Exec:'.G('initTime','viewStartTime').'s Template:'.G('viewStartTime','viewEndTime').'s )';
     
        if(class_exists('Db',false) ) {
            // 显示数据库操作次数
            $showTime .= ' '.N('db_query').' queries '.N('db_write').' writes ';
        }
        if(MEMORY_LIMIT_ON) {
            // 显示内存开销
            $showTime .= ' ,UseMem:'. number_format((memory_get_usage() - $GLOBALS['_startUseMems'])/1024).' kb';
        }
        $showTime .= ', LoadFile:'.count(get_included_files());
        
        //$fun  =  get_defined_functions();
       // $showTime .= ' | CallFun:'.count($fun['user']).','.count($fun['internal']);
        echo "<p  style='text-align:center;'>$showTime<p>";
}


function fieldoption($fields,$value=null,$space=''){
	$options = explode("\n",$fields['setup']['options']);
	foreach($options as $r) {
		$v = explode("|",$r);
		$k = trim($v[1]);
		$optionsarr[$k] = $v[0];
	}
	if(isset($value)){
		if(strpos($value,',')){
			$value =explode(",",$value);
			$data=array();
			foreach((array)$value as $val){
			$data[]= $optionsarr[$val];
			}
			if($space!=''){
			return implode(stripcslashes($space),$data);
			}else{
			return $data;
			}			
		}else{
			return $optionsarr[$value];
		}
	}else{
		return $optionsarr;
	}
}

function subcat($Categorys ,$parentid = '0',$self = '0', $type = '0',$ismenu='1') {
		$Categorys= $Categorys? $Categorys : F('Categorys');
		$subcat=array();
		if($self)$subcat[$parentid]=$Categorys[$parentid];
		foreach($Categorys as $id=>$cat) {
			if($cat['parentid'] != $parentid)continue;
			if(($cat['ismenu']==$ismenu) && (!$type && $type==$cat['type']))$subcat[$id] = $cat;
		}
		return $subcat;
}

function picstoarr($str=''){
	$data=array();
	$v = explode(":::",$str);
	foreach((array)$v as $r){
		$r=explode('|',$r);
		$res['file']=$r[0];
		$res['desc']=$r[1];
		$data[]=$res;
	}
	return $data;
}

function get_arrparentid($pid, $array=array(),$arrparentid='') {
		if(!is_array($array) || !isset($array[$pid])) return $pid;
		$parentid = $array[$pid]['parentid'];
		$arrparentid = $arrparentid ? $parentid.','.$arrparentid : $parentid;
		if($parentid) {
			$arrparentid = get_arrparentid($parentid,$array, $arrparentid);
		}else{
			$data = array();
			$data['bid'] = $pid;
			$data['arrparentid'] = $arrparentid;
		}

		return $arrparentid;
}

function getform($info,$value='',$form){
	if(empty($form)){
		import ( '@.EXT.Form' );	
		$form = new Form();
	}
	return  $form->$info['type']($info,$value);
}

function getvalidate($info){
        $validate_data=array();
        if($info['minlength']) $validate_data['minlength'] = ' minlength:'.$info['minlength'];
		if($info['maxlength']) $validate_data['maxlength'] = ' maxlength:'.$info['maxlength'];
		if($info['required']) $validate_data['required'] = ' required:true';		
		if($info['pattern'] == 'equalTo'){			
			$equalTo = str_replace('re','',$info['field']);
			$validate_data['pattern'] = ' equalTo:#'.$equalTo;
		}else{
			if($info['pattern']) $validate_data['pattern'] = ' '.$info['pattern'].':true';
		}
        if($info['errormsg']) $errormsg = ' title="'.$info['errormsg'].'"';
        $validate= implode(',',$validate_data);
        $validate= $validate ? 'validate="'.$validate.'" ' : '';
        $parseStr = $validate.$errormsg;
        return $parseStr;
}

function sendmail($tomail,$subject,$body,$config=''){

		if(!$config){
			$config = APP_LANG ?  F('Config_'.LANG_NAME) :  F('Config');
		}

		import("@.EXT.PHPMailer");
		$mail = new PHPMailer();

		if($config['mail_type']==1){
			$mail->IsSMTP();
		}elseif($config['mail_type']==2){
			$mail->IsMail();
		}else{
			if($config['sendmailpath']){
				$mail->Sendmail =$config['mail_sendmail'];
			}else{
				$mail->Sendmail =ini_get('sendmail_path');
			}
			$mail->IsSendmail();
		}
		if($config['mail_auth']){
			$mail->SMTPAuth = true; // 开启SMTP认证
		}else{
			$mail->SMTPAuth = false; // 开启SMTP认证
		}

		$mail->PluginDir=YOURPHP_CORE."Ext/";
		$mail->CharSet='utf-8';
		$mail->SMTPDebug  = false;        // 改为2可以开启调试
		$mail->Host = $config['mail_server'];      // GMAIL的SMTP
		//$mail->SMTPSecure = "ssl"; // 设置连接服务器前缀
		//$mail->Encoding = "base64";
		$mail->Port = $config['mail_port'];    // GMAIL的SMTP端口号
		$mail->Username = $config['mail_user']; // GMAIL用户名,必须以@gmail结尾
		$mail->Password = $config['mail_password']; // GMAIL密码
		//$mail->From ="yourphp@163.com";
		//$mail->FromName = "yourphp企业建站系统";
		$mail->SetFrom($config['mail_from'], $config['site_name']);     //发送者邮箱
		$mail->AddAddress($tomail); //可同时发多个
		//$mail->AddReplyTo('147613338@qq.com', 'yourphp'); //回复到这个邮箱
		//$mail->WordWrap = 50; // 设定 word wrap
		//$mail->AddAttachment("/var/tmp/file.tar.gz"); // 附件1
		//$mail->AddAttachment("/tmp/image.jpg", "new.jpg"); // 附件2
		$mail->IsHTML(true); // 以HTML发送
		$mail->Subject = $subject;
		$mail->Body = $body;
		//$mail->AltBody = "This is the body when user views in plain text format";		//纯文字时的Body
		if(!$mail->Send())
		{
			return false;
		}else{
			return true;
		}
}

function delattach($map=''){
		$model = M('Attachment');
		$att= $model->field('filepath')->where($map)->select();
		if($att){
			foreach((array)$att as $key=> $r){
				unlink('.'.YP_PATH.$r['filepath']);
			}
			$r = $model->where($map)->delete();
		}
		return  false!==$r ? true : false;
}

function template_file($module='',$path='',$ext='html'){
	$sysConfig = F('sys.config');
	$path= $path ? $path : YOURPHP_PATH.'Template/'.$sysConfig['DEFAULT_THEME'].'/';
	$tempfiles = dir_list($path,$ext);
	foreach ($tempfiles as $key=>$file){
		$dirname = basename($file);
		if($module){
			if(strstr($dirname,$module.'_')) {
				$arr[$key]['name'] =  substr($dirname,0,strrpos($dirname, '.'));
				$arr[$key]['value'] =  substr($arr[$key]['name'],strpos($arr[$key]['name'], '_')+1);
				$arr[$key]['filename'] = $dirname;
				$arr[$key]['filepath'] = $file;
			}
		}else{
			$arr[$key]['name'] = substr($dirname,0,strrpos($dirname, '.'));
			$arr[$key]['value'] =  substr($arr[$key]['name'],strpos($arr[$key]['name'], '_')+1);
			$arr[$key]['filename'] = $dirname;
			$arr[$key]['filepath'] = $file;
		}
	}
	return  $arr;
}

function fileext($filename) {
	return strtolower(trim(substr(strrchr($filename, '.'), 1, 10)));
}

function dir_path($path) {
	$path = str_replace('\\', '/', $path);
	if(substr($path, -1) != '/') $path = $path.'/';
	return $path;
}

function dir_create($path, $mode = 0777) {
	if(is_dir($path)) return TRUE;
	$ftp_enable = 0;
	$path = dir_path($path);
	$temp = explode('/', $path);
	$cur_dir = '';
	$max = count($temp) - 1;
	for($i=0; $i<$max; $i++) {
		$cur_dir .= $temp[$i].'/';
		if (@is_dir($cur_dir)) continue;
		@mkdir($cur_dir, $mode,true);
		@chmod($cur_dir, $mode);
	}
	return is_dir($path);
}

function mk_dir($dir, $mode = 0777) {
    if (is_dir($dir) || @mkdir($dir, $mode))
        return true;
    if (!mk_dir(dirname($dir), $mode))
        return false;
    return @mkdir($dir, $mode);
}

function dir_copy($fromdir, $todir) {
	$fromdir = dir_path($fromdir);
	$todir = dir_path($todir);
	if (!is_dir($fromdir)) return FALSE;
	if (!is_dir($todir)) dir_create($todir);
	$list = glob($fromdir.'*');
	if (!empty($list)) {
		foreach($list as $v) {
			$path = $todir.basename($v);
			if(is_dir($v)) {
				dir_copy($v, $path);
			} else {
				copy($v, $path);
				@chmod($path, 0777);
			}
		}
	}
    return TRUE;
}

function dir_list($path, $exts = '', $list= array()) {
	$path = dir_path($path);
	$files = glob($path.'*');
	foreach($files as $v) {
		$fileext = fileext($v);
		if (!$exts || preg_match("/\.($exts)/i", $v)) {
			$list[] = $v;
			if (is_dir($v)) {
				$list = dir_list($v, $exts, $list);
			}
		}
	}
	return $list;
}
  
function dir_tree($dir, $parentid = 0, $dirs = array()) {
	if ($parentid == 0) $id = 0;
	$list = glob($dir.'*');
	foreach($list as $v) {
		if (is_dir($v)) {
            $id++;
			$dirs[$id] = array('id'=>$id,'parentid'=>$parentid, 'name'=>basename($v), 'dir'=>$v.'/');
			$dirs = dir_tree($v.'/', $id, $dirs);
		}
	}
	return $dirs;
}


function dir_delete($dir) {
	//$dir = dir_path($dir);
	if (!is_dir($dir)) return FALSE; 
	$handle = opendir($dir); //打开目录
	while(($file = readdir($handle)) !== false) {
	        if($file == '.' || $file == '..')continue;
			$d = $dir.DIRECTORY_SEPARATOR.$file;
	        is_dir($d) ? dir_delete($d) : @unlink($d);
	}
	closedir($handle);
	return @rmdir($dir);
}

function toDate($time, $format = 'Y-m-d H:i:s') {
	if (empty ( $time )) {
		return '';
	}
	$format = str_replace ( '#', ':', $format );
	return date ($format, $time );
}
function savecache($name = '',$id='') {
	$Model = M ( $name );
	if($name=='Lang'){
		$list = $Model->order('listorder')->select ();
		$pkid = $Model->getPk ();
		$data = array ();
		foreach ( $list as $key => $val ) {
			$data [$val ['mark']] = $val;
		}
		F($name,$data);

	}elseif($name=='Module'){
		$list = $Model->order('listorder')->select ();
		$pkid = $Model->getPk ();
		$data = array ();
		foreach ( $list as $key => $val ){
			$data [$val [$pkid]] = $val;
			$smalldata[$val['name']] =  $val [$pkid];
			if($val['issystem'])$M[$val['name']] =  $val [$pkid];
		}
		F($name,$data);
		F('Mod',$smalldata);
		F('M',$M);
		//savecache

	}elseif($name=='Config'){
		
		$list = $Model->select ();
		$data=$sysdata=$temp=$memberconfig=array();
		foreach($list as $key=>$r) {
			if($r['groupid']==6){
				$sysdata[$r['varname']]=$r['value'];
			}elseif($r['groupid']==3){
				if(APP_LANG)
					$memberconfig_temp[$r['lang']][$r['varname']]=$r['value'];
				else
					$memberconfig[$r['varname']]=$r['value'];
			}else{
				if(APP_LANG)
					if($r['lang']){$temp[$r['lang']][$r['varname']]=$r['value'];}else{$data[$r['varname']]=$r['value'];}
				else
					$data[$r['varname']]=$r['value'];
			}
		}
		if(APP_LANG){
			$lang=F('Lang');
			foreach((array)$lang as $key=>$r){
				$data1=array();
				$data1 = array_merge($temp[$r['id']],$data);
				F('Config_'.$key,$data1);
				F('member.config_'.$key,$memberconfig_temp[$r['id']]);
				if(empty($sysdata['HOME_ISHTML'])){
					@unlink('./index.html');
					@unlink('./'.$key.'/index.html');
				}
			}
		}else{
			F('Config',$data);
			F('member.config',$memberconfig);
			if(empty($sysdata['HOME_ISHTML']))@unlink('./index.html');
		}

		$langs = M('Lang')->field('mark')->select();foreach((array)$langs as $r ) $lang1[]=$r['mark'];
		$sysdata['LANG_LIST'] = 'zh-cn,'.implode(',',$lang1);
		
		F('sys.config',$sysdata);

	}elseif($name=='Category'){

		$data=$smalldata=$temp=array();

		if(APP_LANG){
			$lang=F('Lang');
			foreach((array)$lang as $key=>$r){
				$langid =$r['id'];
				if($langid){
					$lang = $key;
					$list = $Model->where('lang='.$langid)->order('listorder')->select ();
					$pkid = $Model->getPk ();
					$data = $smalldata = array ();
					foreach ( $list as $key => $val ) {
						$data [$val [$pkid]] = $val;
						$smalldata[$val['catdir']] =  $val [$pkid];
					}
					F('Category_'.$lang,$data);
					F('Cat_'.$lang,$smalldata);
				}
			}
		}else{
			$list = $Model->order('listorder')->select ();
			$pkid = $Model->getPk ();
			$data = $smalldata = array ();
			foreach ( $list as $key => $val ) {
				$data [$val [$pkid]] = $val;
				$smalldata[$val['catdir']] =  $val [$pkid];
			}
			F($name,$data);
			F('Cat',$smalldata);
		}
	
	}elseif($name=='Field'){
		if($id){		
			$list = $Model->order('listorder')->where('moduleid='.$id)->select ();
			$pkid = 'field';
			$data = array ();
			foreach ( $list as $key => $val ) {
				$data [$val [$pkid]] = $val;
			}
			$name=$id.'_'.$name;
			F($name,$data);
		}else{
			$module = F('Module');
			foreach ( $module as $key => $val ) {
				savecache($name,$key);
			}
		}
	}elseif($name=='Dbsource'){
		$list = $Model->select ();
		$data = array ();
		foreach ( $list as $key => $val ) {
			$data [$val ['name']] = $val;
		}
		F($name,$data);		
	}else{		
		$list = $Model->order('listorder')->select ();
		$pkid = $Model->getPk ();
		$data = array ();
		foreach ( $list as $key => $val ) {
			$data [$val [$pkid]] = $val;
		}
		F($name,$data);
		if($name=='Urlrule'){
			$config = F('sys.config');
			if($config['URL_URLRULE'])routes_cache($config['URL_URLRULE']); 
		}
	}
	
	return true;
}


function checkfield($fields,$postdata){

		foreach ( $postdata as $key => $val ) {
				$setup=$fields[$key]['setup'];

				if(!empty($fields[$key]['required']) && empty($postdata[$key])) return '';
				//$setup=string2array($fields[$key]['setup']);
				if($setup['safefun']){
					$fun =$setup['safefun'];
					if($fun!='no')
					$postdata[$key] = $fun($postdata[$key]);
				
				}elseif($setup['multiple'] || $setup['inputtype']=='checkbox' || $fields[$key]['type']=='checkbox'){
					$postdata[$key] =  safe_replace(strip_tags($postdata[$key]));
					$postdata[$key] = implode(',',$postdata[$key]);		
				}elseif($fields[$key]['type']=='datetime'){
					$postdata[$key] =strtotime($postdata[$key]);
				}elseif($fields[$key]['type']=='images' || $fields[$key]['type']=='files'){
					$name = $key.'_name';
					$arrdata =array();
					foreach($postdata[$key] as $k=>$res){
						if(!empty($postdata[$key][$k])) $arrdata[]= safe_replace(strip_tags($postdata[$key][$k].'|'.$postdata[$name][$k]));
					}
					$postdata[$key]=implode(':::',$arrdata);
				}elseif($fields[$key]['type']=='attr'){
					if($setup['inputtype']=='images'){
						$name = $key.'_name';
						$price = $key.'_price';
						$arrdata =array();
						foreach($postdata[$key] as $k=>$res){
							if(!empty($postdata[$key][$k])) $arrdata[]= safe_replace(strip_tags($postdata[$key][$k].'|'.$postdata[$name][$k].'|'.$postdata[$price][$k]));
						}
						$postdata[$key]=implode(':::',$arrdata);
					}
				}elseif($fields[$key]['type']=='editor'){
					//自动提取摘要
					if(isset($postdata['add_description']) && $postdata['description'] == '' && isset($postdata[$key])) {
						$content = stripslashes($postdata[$key]);
						$description_length = intval($postdata['description_length']);
						$postdata['description'] = str_cut(str_replace(array("\r\n","\t",'[page]','[/page]','&ldquo;','&rdquo;'), '', strip_tags($content)),$description_length);
						$postdata['description'] = safe_replace($postdata['description']);
					}
					//自动提取缩略图
					if(isset($postdata['auto_thumb']) && $postdata['thumb'] == '' && isset($postdata[$key])) {
						$content = $content ? $content : stripslashes($postdata[$key]);
						$auto_thumb_no = intval($postdata['auto_thumb_no']) * 3;
						if(preg_match_all("/(src)=([\"|']?)([^ \"'>]+\.(gif|jpg|jpeg|bmp|png))\\2/i", $content, $matches)) {
							$postdata['thumb'] = $matches[$auto_thumb_no][0];
						}
					}
				}elseif($fields[$key]['type']=='textarea'){
					$postdata[$key] = safe_replace(strip_tags($postdata[$key]));
				}elseif($key=='aid'){
					$postdata[$key] =  $postdata[$key];
				}else{
					$postdata[$key] =  safe_replace(strip_tags($postdata[$key]));
				}
		}
		return $postdata;
}

function string2array($info) {
        if($info == '') return array();
        $info=stripcslashes($info);
        eval("\$r = $info;");
        return $r;
}


function array2string($info) {
	if($info == '') return '';
	if(!is_array($info)) $string = stripslashes($info);
	foreach($info as $key => $val) $string[$key] = stripslashes($val);
	return addslashes(var_export($string, TRUE));
}

function rand_string($len = 6, $type = '', $addChars = '') {
	$str = '';
	switch ($type) {
		case 0 :
			$chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' . $addChars;
			break;
		case 1 :
			$chars = str_repeat ( '0123456789', 3 );
			break;
		case 2 :
			$chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' . $addChars;
			break;
		case 3 :
			$chars = 'abcdefghijklmnopqrstuvwxyz' . $addChars;
			break;
		default :
			// 默认去掉了容易混淆的字符oOLl和数字01，要添加请使用addChars参数
			$chars = 'ABCDEFGHIJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789' . $addChars;
			break;
	}
	if ($len > 10) { //位数过长重复字符串一定次数
		$chars = $type == 1 ? str_repeat ( $chars, $len ) : str_repeat ( $chars, 5 );
	}
	if ($type != 4) {
		$chars = str_shuffle ( $chars );
		$str = substr ( $chars, 0, $len );
	} else {
		// 中文随机字
		for($i = 0; $i < $len; $i ++) {
			$str .= msubstr ( $chars, floor ( mt_rand ( 0, mb_strlen ( $chars, 'utf-8' ) - 1 ) ), 1 );
		}
	}
	return $str;
}
function sysmd5($str,$key='',$type='sha1'){
	$key =  $key ?  $key : C('ADMIN_ACCESS');
	return hash ( $type, $str.$key );
}
function pwdHash($password, $type = 'md5') {
	return hash ( $type, $password );
}


function authcode($string, $operation = 'DECODE', $key = '', $expiry = 0) 
{
	$ckey_length = 4;   

	$keya = md5(substr($key, 0, 16));
	$keyb = md5(substr($key, 16, 16));
	$keyc = $ckey_length ? ($operation == 'DECODE' ? substr($string, 0, $ckey_length): substr(md5(microtime()), -$ckey_length)) : '';

	$cryptkey = $keya.md5($keya.$keyc);
	$key_length = strlen($cryptkey);

	$string = $operation == 'DECODE' ? base64_decode(substr($string, $ckey_length)) : sprintf('%010d', $expiry ? $expiry + time() : 0).substr(md5($string.$keyb), 0, 16).$string;
	$string_length = strlen($string);

	$result = '';
	$box = range(0, 255);

	$rndkey = array();
	for($i = 0; $i <= 255; $i++) 
	{
		$rndkey[$i] = ord($cryptkey[$i % $key_length]);
	}

	for($j = $i = 0; $i < 256; $i++) 
	{
		$j = ($j + $box[$i] + $rndkey[$i]) % 256;
		$tmp = $box[$i];
		$box[$i] = $box[$j];
		$box[$j] = $tmp;
	}

	for($a = $j = $i = 0; $i < $string_length; $i++) 
	{
		$a = ($a + 1) % 256;
		$j = ($j + $box[$a]) % 256;
		$tmp = $box[$a];
		$box[$a] = $box[$j];
		$box[$j] = $tmp;
		$result .= chr(ord($string[$i]) ^ ($box[($box[$a] + $box[$j]) % 256]));
	}

	if($operation == 'DECODE') 
	{
		if((substr($result, 0, 10) == 0 || substr($result, 0, 10) - time() > 0) && substr($result, 10, 16) == substr(md5(substr($result, 26).$keyb), 0, 16)) 
		{
			return substr($result, 26);
		} 
		else 
		{
			return '';
		}
	} 
	else 
	{
		return $keyc.str_replace('=', '', base64_encode($result));
	}
}



//字符串截取
function str_cut($sourcestr,$cutlength,$suffix='...')
{
	$str_length = strlen($sourcestr);
	if($str_length <= $cutlength) {
		return $sourcestr;
	}
	$returnstr='';	
	$n = $i = $noc = 0;
	while($n < $str_length) {
			$t = ord($sourcestr[$n]);
			if($t == 9 || $t == 10 || (32 <= $t && $t <= 126)) {
				$i = 1; $n++; $noc++;
			} elseif(194 <= $t && $t <= 223) {
				$i = 2; $n += 2; $noc += 2;
			} elseif(224 <= $t && $t <= 239) {
				$i = 3; $n += 3; $noc += 2;
			} elseif(240 <= $t && $t <= 247) {
				$i = 4; $n += 4; $noc += 2;
			} elseif(248 <= $t && $t <= 251) {
				$i = 5; $n += 5; $noc += 2;
			} elseif($t == 252 || $t == 253) {
				$i = 6; $n += 6; $noc += 2;
			} else {
				$n++;
			}
			if($noc >= $cutlength) {
				break;
			}
	}
	if($noc > $cutlength) {
			$n -= $i;
	}
	$returnstr = substr($sourcestr, 0, $n);
 

	if ( substr($sourcestr, $n, 6)){
          $returnstr = $returnstr . $suffix;//超过长度时在尾处加上省略号
      }
	return $returnstr;
}

function IP_NAME($ip='',$file='UTFWry.dat') {
	import("@.EXT.IpLocation");
	$iplocation = new IpLocation($file);
	$location = $iplocation->getlocation($ip);
	return $location;
}

function byte_format($input, $dec=0)
{
  $prefix_arr = array("B", "K", "M", "G", "T");
  $value = round($input, $dec);
  $i=0;
  while ($value>1024)
  {
     $value /= 1024;
     $i++;
  }
  $return_str = round($value, $dec).$prefix_arr[$i];
  return $return_str;
}


function build_verify ($length=4,$mode=1) {
    return rand_string($length,$mode);
}


function make_urlrule($url,$lang,$action,$MOREREQUEST=''){
	$url=trim( str_replace(C('URL_HTML_SUFFIX'),'',$url),'/');;
	$langstr = '('.implode('|',$lang).')?\/?';

	$rule=str_replace(array('{$module}','{$moduleid}','{$year}','{$month}','{$day}','{$catid}','{$id}','{$p}','/'),
		array('([A-Z]{1}[a-z]+)','(\d+)','(\d+)','(\d+)','(\d+)','(\d+)','(\d+)','(\d+)','\/'),$url);
	
	if(strstr($url,'{$parentdir')){
		$rule1=str_replace('{$parentdir}{$catdir}','([\w]+)',$rule);
		$varurl=str_replace(array('{$parentdir}','/'),array('','\/'),$url);
		$varurl = preg_replace('/{([\w\$]+)}/', '{([\w\$]+)}',$varurl);

		$rule1 = $langstr.$rule1;
		$varurl = '{([\w\$]+)}\/'.$varurl;
		$tempurl = str_replace(array('{$parentdir}'),array(''),$url);
		$data = " '$rule1' =>array( '{\$l}/$tempurl', '$varurl','$action'),\n";


		$rule1=str_replace('{$parentdir}{$catdir}','([\w]+)\/?([\w\/]+)?\/([\w]+)?',$rule);
		$varurl=str_replace(array('{$parentdir}{$catdir}','/'),array('{$parentdir}{$parentdirs}{$catdir}','\/'),$url);
		$varurl = preg_replace('/{([\w\$]+)}/', '{([\w\$]+)}',$varurl);

		$rule1 = $langstr.$rule1;
		$varurl = '{([\w\$]+)}\/'.$varurl;
		$tempurl = str_replace(array('{$parentdir}{$catdir}'),array('{$parentdir}{$parentdirs}{$catdir}'),$url);
		$data .= " '$rule1' =>array( '{\$l}/$tempurl', '$varurl','$action')";
	}else{
		$rule= $langstr.str_replace(array('{$catdir}','/'),array('([\w]+)','\/'),$rule);
		$varurl=str_replace(array('/'),array('\/'),$url);
		$varurl = preg_replace('/{([\w\$]+)}/', '{([\w\$]+)}',$varurl); 
		$varurl = '{([\w\$]+)}\/'.$varurl;
		$data = " '$rule' =>array( '{\$l}/$url', '$varurl','$action')";
	}			
	return $data;
}

function routes_cache($URL_URLRULE=''){			
 
			$Lang=F('Lang');
			foreach((array)$Lang as $key =>$r){$langarr[]=$key;}
			$langstr =implode('|',$langarr);
			$langurlstr = ' \'('.$langstr.')\'  =>array( \'{$l}\', \'{([\w\$]+)}\',\'index\'),'."\n";
			 
			$tagurl= ' \'('.$langstr.')?\/?(Tags)\' =>array( \'{$l}/{$m}\', \'{([\w\$]+)}\/{([\w\$]+)}\',\'index\'),'."\n";
			$tagurl .= ' \'('.$langstr.')?\/?(Tags)\/([A-Z]{1}[a-z]+)?-?(\w+)?-?(\d+)?\' =>array( \'{$l}/{$m}/{$module}-{$tag}-{$p}\', \'{([\w\$]+)}\/{([\w\$]+)}\/{([\w\$]+)}-{([\w\$]+)}-{([\w\$]+)}\',\'index\'),'."\n";
 

			$URL_URLRULE = $URL_URLRULE ? $URL_URLRULE : C('URL_URLRULE'); 
			$urlrule = is_array($URL_URLRULE) ?  $URL_URLRULE : explode(':::',$URL_URLRULE);
			$list=explode('|',$urlrule[1]);
			$show=explode('|',$urlrule[0]);
			$listurls[]= make_urlrule($show[1],$langarr,'show');
			$listurls[]= make_urlrule($show[0],$langarr,'show');
			$listurls[]= make_urlrule($list[1],$langarr,'index');
			$listurls[]= make_urlrule($list[0],$langarr,'index');		
		
			$url = implode(",\n",$listurls).','."\n";
			file_put_contents(DATA_PATH.'Routes.php', "<?php\nreturn array(\n" .$langurlstr.$tagurl.$url."\n);\n?>");
			if(is_file(CACHE_PATH.'~runtime.php'))@unlink(CACHE_PATH.'~runtime.php');
}

function HOMEURL($lang){
	if(C('URL_M')==1)$index= YP_PATH.'index.php/';
	$lang= C('URL_LANG')!=$lang ? $lang : '';
	if(C('URL_M') > 0){
		$url =$lang ? YP_PATH.'/'.$index.$lang.'/' :  YP_PATH.'/';
	}else{	
		if(C('HOME_ISHTML')){
			$url = $lang ? '/'.$lang.'/' : '/';
		}else{
			$url =$lang ?  YP_APP.'?l='.$lang :  YP_PATH.'/';
		}
	}
	return $url;
}
function URL($url='',$params=array()) { 
	
	if(APP_LANG)$lang = getlang();

	if(!empty($url)){
		list($path, $query) = explode('?',$url);
		list($group, $a) = explode('/',$path);
		list($g, $m) = explode('-',$group);
		$params= http_build_query($params);
		$params = !empty($params) ? '&' . $params : '';
		$query =  !empty($query) ? '&'.$query : '';
		//parse_str($_SERVER['QUERY_STRING'],$urlarr);	
		if($lang) $langurl = '&l='.$lang;
		if (strcasecmp($g,'Home')== 0){
			$url = YP_PATH.'/index.php?m='.$m.'&a='.$a.$query.$params.$langurl;
		}else{
			$url = YP_PATH.'/index.php?g='.$g.'&m='.$m.'&a='.$a.$query.$params.$langurl;
		}
	}else{
		if(C('URL_M')==1)$index=YP_APP.'/';
		if(C('URL_M') > 0){
			$url = $lang ? YP_PATH.$index.$lang.'/' :  YP_PATH.'/';
		}else{
			$url = $lang ? YP_PATH.'/index.php?l='.$lang :  YP_PATH.'/';
		}
	}
	return $url;
}



function TAGURL($data,$p=''){
	$index= C('URL_M')==1 ? YP_PATH.'index.php/' : YP_PATH.'/';
	if(APP_LANG)$lang=getlang();
	if(C('URL_M')==0){
			if($data['moduleid'] > 0 && $data['moduleid']!=2) $params['moduleid']=$data['moduleid'] ;
			if($data['slug']) $params['tag']=$data['slug'] ;
			if($lang)$params['l']=$lang;			
			$url=URL('Home-Tags/index',$params);
			if($p)
				$url_str =$url.'|'.$url.'&p=$p';
			else
				$url_str=$url;
	}else{
			$tag = $data['slug'] ? $data['slug'] : '';
			$module = ($data['moduleid'] > 0 && $data['moduleid']!=2) ? $data['module'] : ''; 
			$langurl = $lang ? $lang.'/' : '' ;
			$url=$index.$langurl.'Tags/';
			if($tag)$urls['tag']=$tag;
			if($module)$urls['module']=$module;
			$url_str=implode('-',$urls);
			if($urls || $p)$url_str=$url_str.C('URL_HTML_SUFFIX');
			if($p){
				$url_str = $url.$url_str.'|';
				$urls['$p']='$p';
				$url_str .= $url.implode('-',$urls).C('URL_HTML_SUFFIX');
			}else{
				$url_str = $url.$url_str;
			}

	}
	return $url_str;
}
	 
function getlang($have=''){
	if($have){
		if(strcasecmp(GROUP_NAME,'Admin')== 0)
			$lang =  LANG_NAME;
		else
			$lang =  $_REQUEST['l'] ? $_REQUEST['l'] : C('URL_LANG');
	}else{
		if(strcasecmp(GROUP_NAME,'Admin')== 0)
			$lang =  C('URL_LANG')!= LANG_NAME ? LANG_NAME : '';
		else
			$lang = $_REQUEST['l'] && C('URL_LANG')!=$_REQUEST['l'] ? $_REQUEST['l'] : '';
	}
	return $lang;
}

function geturl($cat,$data='',$Urlrule=''){
		//$Urlrule =F('Urlrule');
		$id=$data['id']; 
		$URL_MODEL =C('URL_M');
		if(APP_LANG)$lang = getlang();

		$parentdir = $cat['parentdir'];
		$catdir = $cat['catdir'];
		if($data['createtime'])$year = date('Y',$data['createtime']);
		if($data['createtime'])$month = date('m',$data['createtime']);
		if($data['createtime'])$day = date('d',$data['createtime']);
		$module = $cat['module'];
		$moduleid =$cat['moduleid'];
		$catid=$cat['id'];
		
		if($cat['ishtml']){
			if($cat['urlruleid'] && $Urlrule){
				$showurlrule = $Urlrule[$cat['urlruleid']]['showurlrule'];
				$listurlrule = $Urlrule[$cat['urlruleid']]['listurlrule'];
			}else{
				echo 'This cat has not urlruleid or no Urlrule.';exit;
			}
		}else{
			if($URL_MODEL==0){
				$langurl = $lang ?  '&l='.LANG_NAME : '';
				if($id){
					$url[] = U("Home/$cat[module]/show?id=$id".$langurl);
					$url[] = U("Home/$cat[module]/show?id=".$id.$langurl.'&p={$p}');	
				}else{
					$url[] = U("Home/$cat[module]/index?id=$cat[id]".$langurl);
					$url[] = U("Home/$cat[module]/index?id=".$cat['id'].$langurl.'&p={$p}');
				}
				$urls = str_replace('g=Admin&','',$url);
				$urls = str_replace('g=Home&','',$url);
			}else{
				$urlrule = explode(':::',C('URL_URLRULE'));
				$showurlrule = $urlrule[0];
				$listurlrule = $urlrule[1];
			}
		}
		if(empty($urls)){
			$index =  $URL_MODEL==1 ? YP_PATH.'/index.php/' : YP_PATH.'/';
			$langurl = $lang ? $lang.'/' : '';
			if($id){
				$urls = str_replace(array('{$parentdir}','{$module}','{$moduleid}','{$catdir}','{$year}','{$month}','{$day}','{$catid}','{$id}'),array($parentdir,$module,$moduleid,$catdir,$year,$month,$day,$catid,$id),$showurlrule);
			}else{
				$urls = str_replace(array('{$parentdir}','{$module}','{$moduleid}','{$catdir}','{$year}','{$month}','{$day}','{$catid}','{$id}'),array($parentdir,$module,$moduleid,$catdir,$year,$month,$day,$catid,$id),$listurlrule);
			}
			$urls = explode('|',$urls);
			$urls[0]=$index.$langurl.$urls[0];
			$urls[1]=$index.$langurl.$urls[1];		
		}
		return $urls;
}


function content_pages($num, $p,$pageurls) {

	$multipage = '';
	$page = 11;
	$offset = 4;
	$pages = $num;
	$from = $p - $offset;
	$to = $p + $offset;
	$more = 0;
	if($page >= $pages) {
		$from = 2;
		$to = $pages-1;
	} else {
		if($from <= 1) {
			$to = $page-1;
			$from = 2;
		} elseif($to >= $pages) {
			$from = $pages-($page-2);
			$to = $pages-1;
		}
		$more = 1;
	}
	if($p>0) {
		$perpage = $p == 1 ? 1 : $p-1;
		if($perpage==1){
			$multipage .= '<a class="a1" href="'.$pageurls[$perpage][0].'">'.L('previous').'</a>';
		}else{
			$multipage .= '<a class="a1" href="'.$pageurls[$perpage][1].'">'.L('previous').'</a>';
		}
		if($p==1) {
			$multipage .= ' <span>1</span>';
		} elseif($p>6 && $more) {
			$multipage .= ' <a href="'.$pageurls[1][0].'">1</a>..';
		} else {
			$multipage .= ' <a href="'.$pageurls[1][0].'">1</a>';
		}
	}
	for($i = $from; $i <= $to; $i++) {
		if($i != $p) {
			$multipage .= ' <a href="'.$pageurls[$i][1].'">'.$i.'</a>';
		} else {
			$multipage .= ' <span>'.$i.'</span>';
		}
	}
	if($p<$pages) {
		if($p<$pages-5 && $more) {
			$multipage .= ' ..<a href="'.$pageurls[$pages][1].'">'.$pages.'</a> <a class="a1" href="'.$pageurls[$p+1][1].'">'.L('next').'</a>';
		} else {
			$multipage .= ' <a href="'.$pageurls[$pages][1].'">'.$pages.'</a> <a class="a1" href="'.$pageurls[$p+1][1].'">'.L('next').'</a>';
		}
	} elseif($p==$pages) {
		$multipage .= ' <span>'.$pages.'</span> <a class="a1" href="'.$pageurls[$p][1].'">'.L('next').'</a>';
	}
	return $multipage;
}

function thumb($f, $tw=300, $th=300 ,$autocat=0, $nopic = 'nopic.jpg',$t=''){
	if(strstr($f,'://')) return $f;
	if(empty($f)) return YP_PUB.'/Images/'.$nopic;
	$f= '.'.str_replace(YP_PATH,'',$f);
	
	$temp = array(1=>'gif', 2=>'jpeg', 3=>'png');
	list($fw, $fh, $tmp) = getimagesize($f);
	if(empty($t)){
		if($fw>$tw && $fh>$th){
			$pathinfo = pathinfo($f);
			$t = $pathinfo['dirname'].'/thumb_'.$tw.'_'.$th.'_'.$pathinfo['basename'];
			if(is_file($t)){
				return  YP_PATH.substr($t,1);
			}
		}else{
			return  YP_PATH.substr($f,1);
		}		
	}
	
	if(!$temp[$tmp]){	return false; }

	if($autocat){
		if($fw/$tw > $fh/$th){
		$fw = $tw * ($fh/$th);
		}else{
		$fh = $th * ($fw/$tw);
		}
	}else{

		 $scale = min($tw/$fw, $th/$fh); // 计算缩放比例
            if($scale>=1) {
                // 超过原图大小不再缩略
                $tw   =  $fw;
                $th  =  $fh;
            }else{
                // 缩略图尺寸
                $tw  = (int)($fw*$scale);
                $th = (int)($fh*$scale);
            }
	}

	$tmp = $temp[$tmp];
	$infunc = "imagecreatefrom$tmp";
	$outfunc = "image$tmp";
	$fimg = $infunc($f);

	if($tmp != 'gif' && function_exists('imagecreatetruecolor')){
		$timg = imagecreatetruecolor($tw, $th);
	}else{
		$timg = imagecreate($tw, $th);
	}


	if(function_exists('imagecopyresampled'))
		imagecopyresampled($timg, $fimg, 0,0, 0,0, $tw,$th, $fw,$fh);
	else
		imagecopyresized($timg, $fimg, 0,0, 0,0, $tw,$th, $fw,$fh);
	if($tmp=='gif' || $tmp=='png') {
		$background_color  =  imagecolorallocate($timg,  0, 255, 0);  //  指派一个绿色
		imagecolortransparent($timg, $background_color);  //  设置为透明色，若注释掉该行则输出绿色的图
	}
	$outfunc($timg, $t);
	imagedestroy($timg);
	imagedestroy($fimg);
	return  YP_PATH.substr($t,1);
}


function Pinyin($_String) {
$_DataKey = "a|ai|an|ang|ao|ba|bai|ban|bang|bao|bei|ben|beng|bi|bian|biao|bie|bin|bing|bo|bu|ca|cai|can|cang|cao|ce|ceng|cha".
   "|chai|chan|chang|chao|che|chen|cheng|chi|chong|chou|chu|chuai|chuan|chuang|chui|chun|chuo|ci|cong|cou|cu|".
   "cuan|cui|cun|cuo|da|dai|dan|dang|dao|de|deng|di|dian|diao|die|ding|diu|dong|dou|du|duan|dui|dun|duo|e|en|er".
   "|fa|fan|fang|fei|fen|feng|fo|fou|fu|ga|gai|gan|gang|gao|ge|gei|gen|geng|gong|gou|gu|gua|guai|guan|guang|gui".
   "|gun|guo|ha|hai|han|hang|hao|he|hei|hen|heng|hong|hou|hu|hua|huai|huan|huang|hui|hun|huo|ji|jia|jian|jiang".
   "|jiao|jie|jin|jing|jiong|jiu|ju|juan|jue|jun|ka|kai|kan|kang|kao|ke|ken|keng|kong|kou|ku|kua|kuai|kuan|kuang".
   "|kui|kun|kuo|la|lai|lan|lang|lao|le|lei|leng|li|lia|lian|liang|liao|lie|lin|ling|liu|long|lou|lu|lv|luan|lue".
   "|lun|luo|ma|mai|man|mang|mao|me|mei|men|meng|mi|mian|miao|mie|min|ming|miu|mo|mou|mu|na|nai|nan|nang|nao|ne".
   "|nei|nen|neng|ni|nian|niang|niao|nie|nin|ning|niu|nong|nu|nv|nuan|nue|nuo|o|ou|pa|pai|pan|pang|pao|pei|pen".
   "|peng|pi|pian|piao|pie|pin|ping|po|pu|qi|qia|qian|qiang|qiao|qie|qin|qing|qiong|qiu|qu|quan|que|qun|ran|rang".
   "|rao|re|ren|reng|ri|rong|rou|ru|ruan|rui|run|ruo|sa|sai|san|sang|sao|se|sen|seng|sha|shai|shan|shang|shao|".
   "she|shen|sheng|shi|shou|shu|shua|shuai|shuan|shuang|shui|shun|shuo|si|song|sou|su|suan|sui|sun|suo|ta|tai|".
   "tan|tang|tao|te|teng|ti|tian|tiao|tie|ting|tong|tou|tu|tuan|tui|tun|tuo|wa|wai|wan|wang|wei|wen|weng|wo|wu".
   "|xi|xia|xian|xiang|xiao|xie|xin|xing|xiong|xiu|xu|xuan|xue|xun|ya|yan|yang|yao|ye|yi|yin|ying|yo|yong|you".
   "|yu|yuan|yue|yun|za|zai|zan|zang|zao|ze|zei|zen|zeng|zha|zhai|zhan|zhang|zhao|zhe|zhen|zheng|zhi|zhong|".
   "zhou|zhu|zhua|zhuai|zhuan|zhuang|zhui|zhun|zhuo|zi|zong|zou|zu|zuan|zui|zun|zuo";
$_DataValue = "-20319|-20317|-20304|-20295|-20292|-20283|-20265|-20257|-20242|-20230|-20051|-20036|-20032|-20026|-20002|-19990".
   "|-19986|-19982|-19976|-19805|-19784|-19775|-19774|-19763|-19756|-19751|-19746|-19741|-19739|-19728|-19725".
   "|-19715|-19540|-19531|-19525|-19515|-19500|-19484|-19479|-19467|-19289|-19288|-19281|-19275|-19270|-19263".
   "|-19261|-19249|-19243|-19242|-19238|-19235|-19227|-19224|-19218|-19212|-19038|-19023|-19018|-19006|-19003".
   "|-18996|-18977|-18961|-18952|-18783|-18774|-18773|-18763|-18756|-18741|-18735|-18731|-18722|-18710|-18697".
   "|-18696|-18526|-18518|-18501|-18490|-18478|-18463|-18448|-18447|-18446|-18239|-18237|-18231|-18220|-18211".
   "|-18201|-18184|-18183|-18181|-18012|-17997|-17988|-17970|-17964|-17961|-17950|-17947|-17931|-17928|-17922".
   "|-17759|-17752|-17733|-17730|-17721|-17703|-17701|-17697|-17692|-17683|-17676|-17496|-17487|-17482|-17468".
   "|-17454|-17433|-17427|-17417|-17202|-17185|-16983|-16970|-16942|-16915|-16733|-16708|-16706|-16689|-16664".
   "|-16657|-16647|-16474|-16470|-16465|-16459|-16452|-16448|-16433|-16429|-16427|-16423|-16419|-16412|-16407".
   "|-16403|-16401|-16393|-16220|-16216|-16212|-16205|-16202|-16187|-16180|-16171|-16169|-16158|-16155|-15959".
   "|-15958|-15944|-15933|-15920|-15915|-15903|-15889|-15878|-15707|-15701|-15681|-15667|-15661|-15659|-15652".
   "|-15640|-15631|-15625|-15454|-15448|-15436|-15435|-15419|-15416|-15408|-15394|-15385|-15377|-15375|-15369".
   "|-15363|-15362|-15183|-15180|-15165|-15158|-15153|-15150|-15149|-15144|-15143|-15141|-15140|-15139|-15128".
   "|-15121|-15119|-15117|-15110|-15109|-14941|-14937|-14933|-14930|-14929|-14928|-14926|-14922|-14921|-14914".
   "|-14908|-14902|-14894|-14889|-14882|-14873|-14871|-14857|-14678|-14674|-14670|-14668|-14663|-14654|-14645".
   "|-14630|-14594|-14429|-14407|-14399|-14384|-14379|-14368|-14355|-14353|-14345|-14170|-14159|-14151|-14149".
   "|-14145|-14140|-14137|-14135|-14125|-14123|-14122|-14112|-14109|-14099|-14097|-14094|-14092|-14090|-14087".
   "|-14083|-13917|-13914|-13910|-13907|-13906|-13905|-13896|-13894|-13878|-13870|-13859|-13847|-13831|-13658".
   "|-13611|-13601|-13406|-13404|-13400|-13398|-13395|-13391|-13387|-13383|-13367|-13359|-13356|-13343|-13340".
   "|-13329|-13326|-13318|-13147|-13138|-13120|-13107|-13096|-13095|-13091|-13076|-13068|-13063|-13060|-12888".
   "|-12875|-12871|-12860|-12858|-12852|-12849|-12838|-12831|-12829|-12812|-12802|-12607|-12597|-12594|-12585".
   "|-12556|-12359|-12346|-12320|-12300|-12120|-12099|-12089|-12074|-12067|-12058|-12039|-11867|-11861|-11847".
   "|-11831|-11798|-11781|-11604|-11589|-11536|-11358|-11340|-11339|-11324|-11303|-11097|-11077|-11067|-11055".
   "|-11052|-11045|-11041|-11038|-11024|-11020|-11019|-11018|-11014|-10838|-10832|-10815|-10800|-10790|-10780".
   "|-10764|-10587|-10544|-10533|-10519|-10331|-10329|-10328|-10322|-10315|-10309|-10307|-10296|-10281|-10274".
   "|-10270|-10262|-10260|-10256|-10254";
$_TDataKey   = explode('|', $_DataKey);
$_TDataValue = explode('|', $_DataValue);
$_Data =  array_combine($_TDataKey, $_TDataValue);
arsort($_Data);
reset($_Data);
$_String= auto_charset($_String,'utf-8','gbk');
$_Res = '';
for($i=0; $i<strlen($_String); $i++) {
      $_P = ord(substr($_String, $i, 1));
      if($_P>160) { $_Q = ord(substr($_String, ++$i, 1)); $_P = $_P*256 + $_Q - 65536; }
      $_Res .= _Pinyin($_P, $_Data);
}
return preg_replace("/[^a-z0-9]*/", '', $_Res);
}

// 自动转换字符集 支持数组转换
function auto_charset($fContents, $from='gbk', $to='utf-8') {
    $from = strtoupper($from) == 'UTF8' ? 'utf-8' : $from;
    $to = strtoupper($to) == 'UTF8' ? 'utf-8' : $to;
    if (strtoupper($from) === strtoupper($to) || empty($fContents) || (is_scalar($fContents) && !is_string($fContents))) {
        //如果编码相同或者非字符串标量则不转换
        return $fContents;
    }
    if (is_string($fContents)) {
        if (function_exists('mb_convert_encoding')) {
            return mb_convert_encoding($fContents, $to, $from);
        } elseif (function_exists('iconv')) {
            return iconv($from, $to, $fContents);
        } else {
            return $fContents;
        }
    } elseif (is_array($fContents)) {
        foreach ($fContents as $key => $val) {
            $_key = auto_charset($key, $from, $to);
            $fContents[$_key] = auto_charset($val, $from, $to);
            if ($key != $_key)
                unset($fContents[$key]);
        }
        return $fContents;
    }
    else {
        return $fContents;
    }
}

function _Pinyin($_Num, $_Data) {
   if    ($_Num>0      && $_Num<160   ) return chr($_Num);
   elseif($_Num<-20319 || $_Num>-10247) return '';
   else {
        foreach($_Data as $k=>$v){ if($v<=$_Num) break; }
        return $k;
   }
}
function payspend($money,$type=1,$note='',$email='',$userid=0,$username=''){
	$data['createtime']=time();
	$data['userid']= $userid;
	$data['username']= $username;
	$data['type']=$type;
	$data['value']=$money;
	$data['note']=$note;
	$r = M('PaySpend')->add($data);
	if($r){
		return true;
	}else{
		return false;
	}
}
function return_url($code,$record){		
		$config = APP_LANG ?  F('Config_'.LANG_NAME) :  F('Config');
		return $config['site_url'].'/index.php?g=User&m=Pay&a=respond&code='.$code.'&record='.$record;
}
function order_pay_status($sn,$value,$amount,$record){
	$config = APP_LANG ?  F('Config_'.LANG_NAME) :  F('Config');

	if($record){
		$data = M('Pay')->where("sn={$sn}")->find();
		if($data['money']==$amount){
			if($value==2){
				$data['paytime']=time();
				$data['status']=2;
				$r = M('Pay')->save($data);
				$r = M('User')->where('id='.$data['userid'])->setInc('amount',$amount);
			}elseif($value==1){
				$data['status']=3;
				$r = M('Pay')->save($data);
			}
		}
	}else{
		$data = M('Order')->where("sn='{$sn}'")->find();		
		if($data['amount']==$amount){
			$data['status'] =1;
			$data['pay_status'] =$value;
			if($value==2)$data['pay_time'] =time();
			$r = M('Order')->save($data);
		}
	}
	return $r;
}

function addslashes_array($array){
	if(get_magic_quotes_gpc())return $array;
	if(!is_array($array))return addslashes($array);
	foreach($array as $k => $val) $array[$k] = addslashes_array($val);
	return $array;
}

function stripslashes_array($array) {
	if(!is_array($array)) return stripslashes($array);
	foreach($array as $k => $val) $array[$k] = stripslashes_array($val);
	return $array;
}

function htmlspecialchars_array($array) {
	if(!is_array($array)) return htmlspecialchars($array,ENT_QUOTES);
	foreach($array as $k => $val) $array[$k] = htmlspecialchars_array($val);
	return $array;
}



function safe_replace($string) {
	$string = trim($string);
	$string = str_replace(array('\\',';','\'','%2527','%27','%20','&', '"', '<', '>','\0','*','{','}','(',')'), array('','','','','','','&amp;', '&quot;', '&lt;', '&gt;','','','','','&#40;','&#41;'), $string);
	//$string=nl2br($string); 
	return $string;
}	
function get_safe_replace($array){
	if(!is_array($array)) return safe_replace(strip_tags($array));
	foreach($array as $k => $val) $array[$k] = get_safe_replace($val);
	return $array;
}

function safe_html_replace($string) 
{ 
	$find_arr = array( "/\\s+/","/<(\\/?)(scrīpt|i?frame|style|html|body|title|link|meta|\\?|\\%)([^>]*?)>/isU","/(<[^>]*)on[a-zA-Z]+\\s*=([^>]*>)/isU"); 
	$replace_arr = array( " ", "＜\\\\1\\\\2\\\\3＞","\\\\1\\\\2", ); 
	$string = preg_replace( $find_arr,$replace_arr,$string); 
	return $string; 
}

function  sql_split($sql,$tablepre) {

	if($tablepre != "yourphp_") $sql = str_replace("yourphp_", $tablepre, $sql);
	//$sql = preg_replace("/TYPE=(InnoDB|MyISAM|MEMORY)( DEFAULT CHARSET=[^; ]+)?/", "ENGINE=\\1 DEFAULT CHARSET=utf8",$sql);
	
	if($r_tablepre != $s_tablepre) $sql = str_replace($s_tablepre, $r_tablepre, $sql);
	$sql = str_replace("\r", "\n", $sql);
	$ret = array();
	$num = 0;
	$queriesarray = explode(";\n", trim($sql));
	unset($sql);
	foreach($queriesarray as $query)
	{
		$ret[$num] = '';
		$queries = explode("\n", trim($query));
		$queries = array_filter($queries);
		foreach($queries as $query)
		{
			$str1 = substr($query, 0, 1);
			if($str1 != '#' && $str1 != '-') $ret[$num] .= $query;
		}
		$num++;
	}
	return $ret;
}

function getcatsql($catid='',$alias=''){
	if(is_numeric($catid)){
		$cid=$catid;
		$category_arr = F('Category_'.LANG_NAME);
		if($category_arr[$catid]['child'])
			$data['sql']=" AND {$alias}catid in(".$category_arr[$catid]['arrchildid'].")";
		else
			$data['sql']=" AND {$alias}catid='$catid' ";
	}elseif($catid){
		$catid_arr=explode(',',$catid);
		$cid=$catid_arr[0];
		if($cid) $data['sql'] =  " AND {$alias}catid in(".$catid.')';
	}else{
		return;
	}
	if($cid){
		$category_arr = $category_arr ? $category_arr : F('Category_'.LANG_NAME);
		$data['m'] = $category_arr[$cid]['module'] ? $category_arr[$cid]['module'] : '';
		if($data['m']!='Guestbook' || $data['m']!='Feedback'){
			$Urlrule = F('Urlrule');
			$urlrule = geturl($category_arr[$cid],'',$Urlrule);
			$data['urlrule']=implode('|',$urlrule);
		}
	}
	return $data;
} 