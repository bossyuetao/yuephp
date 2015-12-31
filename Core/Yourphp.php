<?php
//dezend by http://www.yunlu99.com/ QQ:270656184
class Yourphp
{
	static private $_instance = array();

	static public function Start()
	{
		set_error_handler(array('Yourphp', 'appError'));
		spl_autoload_register(array('Yourphp', 'autoload'));
		Yourphp::buildApp();
		App::run();
		return NULL;
	}

	static private function buildApp()
	{
		$root = str_replace(basename($_SERVER['SCRIPT_NAME']), '', $_SERVER['SCRIPT_NAME']);
		define('YP_PATH', substr($root, 0, -1));
		define('YP_PUB', YP_PATH . '/Statics');
		define('YP_APP', $_SERVER['SCRIPT_NAME']);
		define('TMPL_PATH', YP_PATH . '/Template/');
		define('TEMP_PATH', CACHE_PATH . 'Temp/');
		define('DATA_PATH', CACHE_PATH . 'Data/');
		define('TPL_CACHE', CACHE_PATH . 'Tpl/');
		define('HTML_CACHE', CACHE_PATH . 'Html/');
		$db_config = include CACHE_PATH . 'config.php';

		if (!$db_config) {
			header('location: ./Install');
		}

		$core_config = array('COOKIE_EXPIRE' => 0, 'COOKIE_DOMAIN' => '', 'COOKIE_PATH' => '/', 'COOKIE_PREFIX' => 'YP_', 'DEFAULT_LANG' => 'cn', 'DEFAULT_THEME' => 'Default', 'DEFAULT_GROUP' => 'Home', 'DEFAULT_MODULE' => 'Index', 'DEFAULT_ACTION' => 'index', 'DEFAULT_CHARSET' => 'utf-8', 'DEFAULT_AJAX_RETURN' => 'JSON', 'DEFAULT_JSONP_HANDLER' => 'jsonpReturn', 'DEFAULT_FILTER' => 'htmlspecialchars', 'DB_FIELDTYPE_CHECK' => false, 'DB_FIELDS_CACHE' => 0, 'DB_CHARSET' => 'utf8', 'SESSION_AUTO_START' => true, 'SESSION_TYPE' => '', 'SESSION_PREFIX' => '', 'VAR_SESSION_ID' => 'session_id', 'TMPL_DETECT_THEME' => false, 'TMPL_TEMPLATE_SUFFIX' => '.html', 'TMPL_FILE_DEPR' => '_', 'URL_CASE_INSENSITIVE' => false, 'URL_MODEL' => 0, 'URL_PATHINFO_DEPR' => '/', 'URL_PARAMS_BIND' => true, 'URL_404_REDIRECT' => '', 'VAR_GROUP' => 'g', 'VAR_MODULE' => 'm', 'VAR_ACTION' => 'a', 'VAR_AJAX_SUBMIT' => 'ajax', 'VAR_JSONP_HANDLER' => 'callback', 'VAR_TEMPLATE' => 't', 'VAR_FILTERS' => 'filter_exp', 'DEFAULT_THEME' => 'Default', 'DEFAULT_CHARSET' => 'utf-8', 'APP_GROUP_LIST' => 'Home,Admin,User', 'DEFAULT_GROUP' => 'Home', 'USER_AUTH_ON' => true, 'USER_AUTH_TYPE' => 1, 'USER_AUTH_KEY' => 'authId', 'ADMIN_AUTH_KEY' => 'administrator', 'USER_AUTH_MODEL' => 'User', 'AUTH_PWD_ENCODER' => 'md5', 'NOT_AUTH_MODULE' => '', 'REQUIRE_AUTH_MODULE' => '', 'NOT_AUTH_ACTION' => '', 'REQUIRE_AUTH_ACTION' => '', 'GUEST_AUTH_ON' => false, 'GUEST_AUTH_ID' => 0, 'DB_LIKE_FIELDS' => 'name|remark', 'RBAC_ROLE_TABLE' => $db_config['DB_PREFIX'] . 'role', 'RBAC_USER_TABLE' => $db_config['DB_PREFIX'] . 'role_user', 'RBAC_ACCESS_TABLE' => $db_config['DB_PREFIX'] . 'access', 'RBAC_NODE_TABLE' => $db_config['DB_PREFIX'] . 'node', 'DEFAULT_HOME_THEME' => 'Default', 'TMPL_CACHE_ON' => 0, 'TMPL_CACHE_TIME' => 3600, 'DATA_CACHE_TYPE' => 'file');
		$sys_config = f('sys.config');

		if ($sys_config['URL_MODEL']) {
			$sys_config['URL_ROUTE_RULES'] = f('Routes');
		}

		$sys_config = ($sys_config ? $sys_config : array());
		$config = array_merge($core_config, $db_config, $sys_config);
		c($config);
		c('M', f('M'));
		$cache_model = array('Lang', 'Menu', 'Config', 'Module', 'Role', 'Category', 'Posid', 'Field', 'Type', 'Urlrule', 'Dbsource');

		if (empty($sys_config['ADMIN_ACCESS'])) {
			foreach ($cache_model as $r) {
				savecache($r);
			}
		}

		return NULL;
	}

	static public function autoload($class)
	{
		$libPath = YOURPHP_PATH . 'Yourphp/';
		$group = (defined('GROUP_NAME') ? GROUP_NAME . '/' : '');
		$file = $class . '.class.php';

		if (substr($class, -5) == 'Model') {
			if (require_cache($libPath . $group . 'Model/' . $file)) {
				return NULL;
			}
		}
		else if (substr($class, -6) == 'Action') {
			if (is_file($libPath . $file)) {
				if (require_cache($libPath . $file)) {
					return NULL;
				}
			}

			if (require_cache($libPath . $group . $file)) {
				return NULL;
			}
		}
		else if (substr($class, 0, 5) == 'Cache') {
			if (require_cache(YOURPHP_CORE . 'Driver/Cache/' . $file)) {
				return NULL;
			}
		}
		else if (substr($class, 0, 2) == 'Db') {
			if (require_cache(YOURPHP_CORE . 'Driver/Db/' . $file)) {
				return NULL;
			}
		}
		else {
			return NULL;
		}
	}

	static public function instance($class, $method = '')
	{
		$identify = $class . $method;

		if (!isset(self::$_instance[$identify])) {
			if (class_exists($class)) {
				$o = new $class();
				if (!empty($method) && method_exists($o, $method)) {
					self::$_instance[$identify] = call_user_func_array(array(&$o, $method));
				}
				else {
					self::$_instance[$identify] = $o;
				}
			}
			else {
				halt(l('_CLASS_NOT_EXIST_') . ':' . $class);
			}
		}

		return self::$_instance[$identify];
	}

	static public function appError($errno, $errstr, $errfile, $errline)
	{
		switch ($errno) {
		case 1:
		case 4:
		case 16:
		case 64:
		case 256:
			ob_end_clean();
			$errorStr = $errstr . ' ' . $errfile . 'Line: ' . $errline . ' .';
			halt('ERROR:' . $errorStr);
			break;

		case 2048:
		case 512:
		case 1024:
		default:
			break;
		}
	}
}

class App
{
	static public function init()
	{
		date_default_timezone_set('PRC');

		if ($_GET['g'] == 'Admin') {
			$admin_config = array('DEFAULT_THEME' => 'Default', 'URL_ROUTER_ON' => false, 'TMPL_CACHE_ON' => true, 'TMPL_CACHE_TIME' => 3600, 'HTML_CACHE_ON' => 0, 'URL_MODEL' => 0);
			c($admin_config);
		}

		App::dispatch();
		$_REQUEST = array_merge($_POST, $_GET);
		APP::readcache();
		$zlib = ini_get('zlib.output_compression');

		if (empty($zlib)) {
			ob_start('ob_gzhandler');
		}

		define('IS_GET', $_SERVER['REQUEST_METHOD'] == 'GET' ? true : false);
		define('IS_POST', $_SERVER['REQUEST_METHOD'] == 'POST' ? true : false);
		define('IS_AJAX', (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && (strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest')) || !empty($_POST[c('VAR_AJAX_SUBMIT')]) || !empty($_GET[c('VAR_AJAX_SUBMIT')]) ? true : false);

		if (intval($_GET['iscreatehtml'])) {
			$group = '';
			$sysConfig = f('sys.config');
			define('THEME_NAME', $sysConfig['DEFAULT_THEME']);
		}
		else {
			$group = (defined('GROUP_NAME') ? GROUP_NAME : '');

			if (GROUP_NAME == 'Home') {
				$group = '';
			}

			define('THEME_NAME', c('DEFAULT_THEME'));
		}

		define('THEME_PATH', YOURPHP_PATH . 'Template/' . THEME_NAME . '/' . ($group ? $group . '/' : ''));
		define('GROUP_TMPL_PATH', TMPL_PATH . THEME_NAME . '/' . ($group ? $group . '/' : ''));
		c('CACHE_PATH', TPL_CACHE . (intval($_GET['iscreatehtml']) ? 'Home' : GROUP_NAME) . '/');
		App::checklang();
		return NULL;
	}

	static public function exec()
	{
		if (!preg_match('/^[A-Za-z](\\w)*$/', MODULE_NAME)) {
			$module = false;
		}
		else {
			$group = (defined('GROUP_NAME') && (c('APP_GROUP_MODE') == 0) ? GROUP_NAME . '/' : '');
			$module = a($group . MODULE_NAME);
		}

		if (!$module) {
			if (function_exists('__hack_module')) {
				$module = __hack_module();

				if (!is_object($module)) {
					return NULL;
				}
			}
			else {
				$module = a($group . 'Empty');

				if (!$module) {
					_404(l('_MODULE_NOT_EXIST_') . ':' . MODULE_NAME);
				}
			}
		}

		$action = (c('ACTION_NAME') ? c('ACTION_NAME') : ACTION_NAME);
		c('TEMPLATE_NAME', THEME_PATH . MODULE_NAME . c('TMPL_FILE_DEPR') . $action . c('TMPL_TEMPLATE_SUFFIX'));
		$action .= c('ACTION_SUFFIX');

		try {
			if (!preg_match('/^[A-Za-z](\\w)*$/', $action)) {
				throw new ReflectionException();
			}

			$method = new ReflectionMethod($module, $action);

			if ($method->isPublic()) {
				$class = new ReflectionClass($module);

				if ($class->hasMethod('_before_' . $action)) {
					$before = $class->getMethod('_before_' . $action);

					if ($before->isPublic()) {
						$before->invoke($module);
					}
				}

				if (c('URL_PARAMS_BIND') && (0 < $method->getNumberOfParameters())) {
					switch ($_SERVER['REQUEST_METHOD']) {
					case 'POST':
						$vars = $_POST;
						break;

					case 'PUT':
						parse_str(file_get_contents('php://input'), $vars);
						break;

					default:
						$vars = $_GET;
					}

					$params = $method->getParameters();

					foreach ($params as $param) {
						$name = $param->getName();

						if (isset($vars[$name])) {
							$args[] = $vars[$name];
						}
						else if ($param->isDefaultValueAvailable()) {
							$args[] = $param->getDefaultValue();
						}
						else {
							throw_exception(l('_PARAM_ERROR_') . ':' . $name);
						}
					}

					$method->invokeArgs($module, $args);
				}
				else {
					$method->invoke($module);
				}

				if ($class->hasMethod('_after_' . $action)) {
					$after = $class->getMethod('_after_' . $action);

					if ($after->isPublic()) {
						$after->invoke($module);
					}
				}
			}
			else {
				throw new ReflectionException();
			}
		}
		catch (ReflectionException $e) {
			$method = new ReflectionMethod($module, '__call');
			$method->invokeArgs($module, array($action, ''));
		}

		return NULL;
	}

	static public function run()
	{
		session(array());
		App::init();
		g('initTime');
		App::exec();
		return NULL;
	}

	static public function dispatch()
	{
		if (c('URL_MODEL')) {
			if (!empty($_GET['s'])) {
				$_SERVER['PATH_INFO'] = $_GET['s'];
			}

			unset($_GET['s']);
			$path_info = trim(str_replace(c('URL_HTML_SUFFIX'), '', $_SERVER['PATH_INFO']), '/');
			$routes = f('Routes');

			foreach ((array) $routes as $key => $url_r) {
				if ($_GET['a']) {
					continue;
				}

				preg_match_all('/^' . $key . '$/', $path_info, $matches);

				if (!empty($matches[0])) {
					preg_match_all('/' . $url_r[1] . '/', $url_r[0], $matches1);

					foreach ($matches1 as $k => $r) {
						if ($k) {
							$v = str_replace('$', '&', $r[0]);
							$url .= $v . '=' . $matches[$k][0];
						}
					}

					parse_str($url, $urls);
					extract($urls, EXTR_OVERWRITE);
					$lang = ($l ? '_' . $l : '_' . c('DEFAULT_LANG'));
					$catdir = get_safe_replace($urls['catdir']);
					if ($catdir && !$catid) {
						unset($urls['catdir']);
						$Cat = f('Cat' . $lang);
						$urls['catid'] = $catid = $Cat[$catdir];
						unset($Cat);
					}

					if ($catid) {
						$Category = f('Category' . $lang);
						$_GET['m'] = $Category[$catid]['module'];

						if ($url_r[2] == 'index') {
							$urls['id'] = $urls['catid'];
							unset($urls['catid']);
						}
					}
					else if ($module) {
						$_GET['m'] = get_safe_replace($module);
						unset($urls['module']);
					}
					else if ($moduleid) {
						$Module = f('Module');
						$_GET['m'] = $Module[$moduleid]['module'];
						unset($urls['moduleid']);
						unset($Module);
					}

					unset($urls['a']);
					$_GET['a'] = $url_r[2] ? $url_r[2] : c('DEFAULT_ACTION');
					$_GET = array_merge($_GET, $urls);
					unset($urls);
				}
				else {
					continue;
				}
			}
		}

		$g = ($_GET['g'] ? get_safe_replace($_GET['g']) : c('DEFAULT_GROUP'));
		$m = ($_GET['m'] ? get_safe_replace($_GET['m']) : c('DEFAULT_MODULE'));
		$a = ($_GET['a'] ? get_safe_replace($_GET['a']) : c('DEFAULT_ACTION'));

		if ($g != 'Admin') {
			$_GET['l'] = $_GET['l'] ? $_GET['l'] : c('DEFAULT_LANG');
			define('LANG_SET', strtolower($_GET['l']));
		}

		define('GROUP_NAME', $g);
		define('MODULE_NAME', $m);
		define('ACTION_NAME', $a);
	}

	static public function checklang()
	{
		define('LANG_PATH', YOURPHP_PATH . 'Template/' . THEME_NAME . '/lang/');

		if (GROUP_NAME == 'Admin') {
			l(include YOURPHP_PATH . 'Template/Default/Admin/lang/common.php');

			if (is_file(YOURPHP_PATH . 'Template/Default/Admin/lang/' . GROUP_NAME . '_' . strtolower(MODULE_NAME) . '.php')) {
				l(include YOURPHP_PATH . 'Template/Default/Admin/lang/' . GROUP_NAME . '_' . strtolower(MODULE_NAME) . '.php');
			}

			if (intval($_GET['iscreatehtml'])) {
				l(include LANG_PATH . $_SESSION['YP_lang'] . '/common.php');
			}
		}
		else {
			$group = strtolower(GROUP_NAME);
			l(include LANG_PATH . LANG_SET . '/common.php');

			if (is_file(LANG_PATH . LANG_SET . '/' . $group . '.php')) {
				l(include LANG_PATH . LANG_SET . '/' . $group . '.php');
			}

			if (is_file(LANG_PATH . LANG_SET . '/' . $group . '_' . strtolower(MODULE_NAME) . '.php')) {
				l(include LANG_PATH . LANG_SET . '/' . $group . '_' . strtolower(MODULE_NAME) . '.php');
			}

			if (strtolower(MODULE_NAME) == 'order') {
				l(include LANG_PATH . LANG_SET . '/order.php');
			}
		}

		return NULL;
	}

	static public function readcache()
	{
		if (c('HTML_CACHE_ON') && (MODULE_NAME != 'Search')) {
			$id = implode('-', $_GET);
			$cache_time = c('HTML_CACHE_TIME');
			define('HTML_FILE_NAME', HTML_CACHE . MODULE_NAME . '/' . md5(ACTION_NAME . $id) . '.html');
			if (is_file(HTML_FILE_NAME) && (0 < $cache_time)) {
				$filetime = filemtime(HTML_FILE_NAME) + $cache_time;

				if (time() < $filetime) {
					@readfile(HTML_FILE_NAME);
					exit();
				}
			}
		}
	}
}

abstract class Action
{
	protected $view;
	private $name = '';
	protected $tVar = array();
	protected $config = array();

	public function __construct()
	{
		if (method_exists($this, '_initialize')) {
			$this->_initialize();
		}
	}

	protected function getActionName()
	{
		if (empty($this->name)) {
			$this->name = substr(get_class($this), 0, -6);
		}

		return $this->name;
	}

	protected function isAjax()
	{
		if (isset($_SERVER['HTTP_X_REQUESTED_WITH'])) {
			if ('xmlhttprequest' == strtolower($_SERVER['HTTP_X_REQUESTED_WITH'])) {
				return true;
			}
		}

		if (!empty($_POST[c('VAR_AJAX_SUBMIT')]) || !empty($_GET[c('VAR_AJAX_SUBMIT')])) {
			return true;
		}

		return false;
	}

	protected function display($templateFile = '', $charset = '', $contentType = '', $content = '', $prefix = '')
	{
		$this->initView();
		$this->view->display($templateFile, $charset, $contentType, $content, $prefix);
	}

	protected function show($content, $charset = '', $contentType = '', $prefix = '')
	{
		$this->initView();
		$this->view->display('', $charset, $contentType, $content, $prefix);
	}

	protected function fetch($templateFile = '', $content = '', $prefix = '')
	{
		$this->initView();
		return $this->view->fetch($templateFile, $content, $prefix);
	}

	private function initView()
	{
		if (!$this->view) {
			$this->view = Yourphp::instance('View');
		}

		if ($this->tVar) {
			$this->view->assign($this->tVar);
		}
	}

	protected function buildHtml($htmlfile = '', $htmlpath = '', $templateFile = '')
	{
		c('TMPL_CACHE_ON', true);
		c('TMPL_CACHE_TIME', 3600);
		$content = $this->fetch($templateFile);
		$htmlpath = (!empty($htmlpath) ? $htmlpath : YOURPHP_PATH . 'Html/');
		$htmlfile = $htmlpath . $htmlfile . c('HTML_FILE_SUFFIX');

		if (!is_dir(dirname($htmlfile))) {
			mkdir(dirname($htmlfile), 493, true);
		}

		if (false === file_put_contents($htmlfile, $content)) {
			throw_exception(l('_CACHE_WRITE_ERROR_') . ':' . $htmlfile);
		}

		return $content;
	}

	protected function assign($name, $value = '')
	{
		if (is_array($name)) {
			$this->tVar = array_merge($this->tVar, $name);
		}
		else {
			$this->tVar[$name] = $value;
		}
	}

	public function __set($name, $value)
	{
		$this->assign($name, $value);
	}

	public function get($name = '')
	{
		if ('' === $name) {
			return $this->tVar;
		}

		return isset($this->tVar[$name]) ? $this->tVar[$name] : false;
	}

	public function __get($name)
	{
		return $this->get($name);
	}

	public function __isset($name)
	{
		return isset($this->tVar[$name]);
	}

	public function __call($method, $args)
	{
		if (0 === strcasecmp($method, ACTION_NAME . c('ACTION_SUFFIX'))) {
			if (method_exists($this, '_empty')) {
				$this->_empty($method, $args);
			}
			else if (file_exists_case(c('TEMPLATE_NAME'))) {
				$this->display();
			}
			else if (function_exists('__hack_action')) {
				__hack_action();
			}
			else {
				send_http_status(404);
				exit('_ERROR_ACTION_:' . ACTION_NAME);
			}
		}
		else {
			switch (strtolower($method)) {
			case 'ispost':
			case 'isget':
			case 'ishead':
			case 'isdelete':
			case 'isput':
				return strtolower($_SERVER['REQUEST_METHOD']) == strtolower(substr($method, 2));
			case '_get':
				$input = &$_GET;
				break;

			case '_post':
				$input = &$_POST;
				break;

			case '_put':
				parse_str(file_get_contents('php://input'), $input);
				break;

			case '_param':
				switch ($_SERVER['REQUEST_METHOD']) {
				case 'POST':
					$input = $_POST;
					break;

				case 'PUT':
					parse_str(file_get_contents('php://input'), $input);
					break;

				default:
					$input = $_GET;
				}

				if (c('VAR_URL_PARAMS')) {
					$params = $_GET[c('VAR_URL_PARAMS')];
					$input = array_merge($input, $params);
				}

				break;

			case '_request':
				$input = &$_REQUEST;
				break;

			case '_session':
				$input = &$_SESSION;
				break;

			case '_cookie':
				$input = &$_COOKIE;
				break;

			case '_server':
				$input = &$_SERVER;
				break;

			case '_globals':
				$input = &$GLOBALS;
				break;

			default:
				throw_exception('Action' . ':' . $method . l('_METHOD_NOT_EXIST_'));
			}

			if (!isset($args[0])) {
				$data = $input;
			}
			else if (isset($input[$args[0]])) {
				$data = $input[$args[0]];
				$filters = (isset($args[1]) ? $args[1] : c('DEFAULT_FILTER'));

				if ($filters) {
					$filters = explode(',', $filters);

					foreach ($filters as $filter) {
						if (function_exists($filter)) {
							$data = (is_array($data) ? array_map($filter, $data) : $filter($data));
						}
					}
				}
			}
			else {
				$data = (isset($args[2]) ? $args[2] : NULL);
			}

			return $data;
		}
	}

	protected function error($message, $jumpUrl = '', $ajax = false)
	{
		$this->dispatchJump($message, 0, $jumpUrl, $ajax);
	}

	protected function success($message, $jumpUrl = '', $ajax = false)
	{
		$this->dispatchJump($message, 1, $jumpUrl, $ajax);
	}

	protected function ajaxReturn($data, $type = '')
	{
		if (2 < func_num_args()) {
			$args = func_get_args();
			array_shift($args);
			$info = array();
			$info['data'] = $data;
			$info['info'] = array_shift($args);
			$info['status'] = array_shift($args);
			$data = $info;
			$type = ($args ? array_shift($args) : '');
		}

		if (empty($type)) {
			$type = c('DEFAULT_AJAX_RETURN');
		}

		switch (strtoupper($type)) {
		case 'JSON':
			header('Content-Type:application/json; charset=utf-8');
			exit(json_encode($data));
		case 'XML':
			header('Content-Type:text/xml; charset=utf-8');
			exit(xml_encode($data));
		case 'JSONP':
			header('Content-Type:application/json; charset=utf-8');
			$handler = (isset($_GET[c('VAR_JSONP_HANDLER')]) ? $_GET[c('VAR_JSONP_HANDLER')] : c('DEFAULT_JSONP_HANDLER'));
			exit($handler . '(' . json_encode($data) . ');');
		case 'EVAL':
			header('Content-Type:text/html; charset=utf-8');
			exit($data);
		default:
			tag('ajax_return', $data);
		}
	}

	protected function redirect($url, $params = array(), $delay = 0, $msg = '')
	{
		$url = u($url, $params);
		redirect($url, $delay, $msg);
	}

	private function dispatchJump($message, $status = 1, $jumpUrl = '', $ajax = false)
	{
		if ((true === $ajax) || IS_AJAX) {
			$data = (is_array($ajax) ? $ajax : array());
			$data['info'] = $message;
			$data['status'] = $status;
			$data['url'] = $jumpUrl;
			$this->ajaxReturn($data);
		}

		if (is_int($ajax)) {
			$this->assign('waitSecond', $ajax);
		}

		if (!empty($jumpUrl)) {
			$this->assign('jumpUrl', $jumpUrl);
		}

		$this->assign('msgTitle', $status ? l('_OPERATION_SUCCESS_') : l('_OPERATION_FAIL_'));

		if ($this->get('closeWin')) {
			$this->assign('jumpUrl', 'javascript:window.close();');
		}

		$this->assign('status', $status);
		c('HTML_CACHE_ON', false);

		if ($status) {
			$this->assign('message', $message);

			if (!isset($this->waitSecond)) {
				$this->assign('waitSecond', '1');
			}

			if (!isset($this->jumpUrl)) {
				$this->assign('jumpUrl', $_SERVER['HTTP_REFERER']);
			}

			$this->display(YOURPHP_PATH . 'Template/Default/message.html');
		}
		else {
			$this->assign('error', $message);

			if (!isset($this->waitSecond)) {
				$this->assign('waitSecond', '3');
			}

			if (!isset($this->jumpUrl)) {
				$this->assign('jumpUrl', 'javascript:history.back(-1);');
			}

			$this->display(YOURPHP_PATH . 'Template/Default/message.html');
			exit();
		}
	}
}

class View
{
	protected $tVar = array();
	protected $templateFile = '';
	protected $templCacheFile = '';
	public $config = array();

	public function assign($name, $value = '')
	{
		if (is_array($name)) {
			$this->tVar = array_merge($this->tVar, $name);
		}
		else {
			$this->tVar[$name] = $value;
		}
	}

	public function get($name = '')
	{
		if ('' === $name) {
			return $this->tVar;
		}

		return isset($this->tVar[$name]) ? $this->tVar[$name] : false;
	}

	public function set($name, $value)
	{
		$this->tVar[$name] = $value;
	}

	public function display($templateFile, $charset = '', $contentType = '', $content = '', $prefix = '')
	{
		g('viewStartTime');
		$content = $this->fetch($templateFile, $prefix);
		$this->write_cache($content);

		if (empty($charset)) {
			$charset = c('DEFAULT_CHARSET');
		}

		if (empty($contentType)) {
			$contentType = 'text/html';
		}

		header('Content-Type:' . $contentType . '; charset=' . $charset);
		header('Cache-control: private');
		header('X-Powered-By:Yourphp');
		echo $content;
	}

	public function fetch($templateFile = '', $prefix = '')
	{
		if ($templateFile === '') {
			$templateFile = c('TEMPLATE_NAME');
		}
		else if (false === strpos($templateFile, c('TMPL_TEMPLATE_SUFFIX'))) {
			$path = explode(':', $templateFile);
			$action = array_pop($path);
			$module = (!empty($path) ? array_pop($path) : MODULE_NAME);

			if (!empty($path)) {
				$path = dirname(THEME_PATH) . '/' . array_pop($path) . '/';
			}
			else {
				$path = THEME_PATH;
			}

			$action = ($action ? $action : ACTION_NAME);
			$templateFile = $path . $module . '_' . $action . c('TMPL_TEMPLATE_SUFFIX');
		}

		if (!file_exists_case($templateFile)) {
			throw_exception(l('_TEMPLATE_NOT_EXIST_') . '[' . $templateFile . ']');
		}

		if (!is_file($templateFile)) {
			return NULL;
		}

		ob_start();
		ob_implicit_flush(0);
		$params = array('file' => $templateFile, 'prefix' => $prefix);
		$this->_template($params);
		$content = ob_get_clean();

		if (YP_KEY == false) {
			if ((GROUP_NAME == 'Home') || (MODULE_NAME == 'Createhtml')) {
				$content .= '<p style="display:none;">Powered by <a href="http://www.yourphp.cn" target="_blank">Yourphp</p></body></html>';
			}
			else if (GROUP_NAME == 'Admin') {
				if ((MODULE_NAME == 'Index') && (ACTION_NAME == 'index')) {
					$content .= '<div id="footer" class="footer">Powered by <a href="http://www.yourphp.cn" target="_blank">Yourphp</a>&nbsp;' . VERSION . '&nbsp;' . UPDATETIME . ' Copyright 2008-2013</div></body></html>';
				}
				else {
					if (!$this->tVar['waitSecond'] && (MODULE_NAME != 'Attachment') && (MODULE_NAME != 'Field')) {
						$content .= '<p align="center" style="padding-top:10px;">Powered by <a href="http://www.yourphp.cn" target="_blank">Yourphp</a>&nbsp;' . VERSION . '&nbsp;' . UPDATETIME . ' Copyright 2008-2013</p></body></html>';
					}
				}
			}
		}
		else {
			if ((GROUP_NAME == 'Admin') && (MODULE_NAME == 'Index') && (ACTION_NAME == 'index')) {
				$content .= '<div id="footer" class="footer">Powered by <a href="' . $this->tVar['site_url'] . '" target="_blank">' . $this->tVar['site_name'] . '</a>&nbsp;' . VERSION . '&nbsp;' . UPDATETIME . ' Copyright 2008-2013</div></body></html>';
			}
			else {
				$content .= '</body></html>';
			}
		}

		return $content;
	}

	public function write_cache($content)
	{
		if (c('HTML_CACHE_ON') && ('' !== defined('HTML_FILE_NAME'))) {
			if (!is_dir(dirname(HTML_FILE_NAME))) {
				mkdir(dirname(HTML_FILE_NAME), 493, true);
			}

			if (false === file_put_contents(HTML_FILE_NAME, $content)) {
				exit('CACHE WRITE ERROR:' . HTML_FILE_NAME);
			}
		}
	}

	public function _template(&$_data)
	{
		$this->config['cache_path'] = c('CACHE_PATH');
		$this->config['template_suffix'] = c('TMPL_TEMPLATE_SUFFIX');
		$this->config['tmpl_cache'] = c('TMPL_CACHE_ON');
		$this->config['cache_time'] = c('TMPL_CACHE_TIME');
		$this->config['default_tmpl'] = c('TEMPLATE_NAME');
		$this->config['layout_item'] = c('TMPL_LAYOUT_ITEM');
		$this->config['layout_name'] = 'Layout';
		$this->config['layout_no'] = 1;
		$_data['prefix'] = !empty($_data['prefix']) ? $_data['prefix'] : '';
		$this->templateFile = empty($_data['content']) ? $_data['file'] : $_data['content'];
		$l = (APP_LANG ? '_' . $this->tVar['l'] : '');
		$this->templCacheFile = $this->config['cache_path'] . $_data['prefix'] . md5($this->templateFile) . $l . '.php';
		if (!$this->checkCache($_data['file']) || !$this->config['tmpl_cache']) {
			$this->loadTemplate();
		}

		extract($this->tVar, EXTR_OVERWRITE);
		include $this->templCacheFile;
	}

	public function loadTemplate()
	{
		if (is_file($this->templateFile)) {
			$tmplContent = file_get_contents($this->templateFile);
		}

		if ($this->config['layout_no']) {
			if (false !== strpos($tmplContent, '{__NOLAYOUT__}')) {
				$tmplContent = str_replace('{__NOLAYOUT__}', '', $tmplContent);
			}
			else {
				$layoutFile = THEME_PATH . $this->config['layout_name'] . $this->config['template_suffix'];
				$tmplContent = str_replace('{__CONTENT__}', $tmplContent, file_get_contents($layoutFile));
			}
		}

		$tmplContent = $this->compiler($tmplContent);
		$dir = dirname($this->templCacheFile);

		if (!is_dir($dir)) {
			mkdir($dir, 493, true);
		}

		if (false === file_put_contents($this->templCacheFile, trim($tmplContent))) {
			throw_exception(l('_CACHE_WRITE_ERROR_') . ':' . $this->templCacheFile);
		}

		return NULL;
	}

	protected function compiler($tmplContent)
	{
		$tmplContent = $this->parse($tmplContent);
		$tmplContent = '<?php if (!defined(\'Yourphp\')) die(\'Yourphp\');?>' . $tmplContent;
		$tmplContent = str_replace('?><?php', '', $tmplContent);

		if (!YP_KEY) {
			$tmplContent = str_replace('</title>', ' - Powered by Yourphp</title>', $tmplContent);
		}

		return $tmplContent;
	}

	protected function parse($str, $tpl_path = '')
	{
		$tpl_path = ($tpl_path ? $tpl_path : GROUP_TMPL_PATH);
		$search_str = array(
			'find'    => array('YP_PATH', 'YP_APP', 'YP_PUB'),
			'replace' => array(YP_PATH, YP_PATH . '/index.php', YP_PATH . '/Statics')
			);
		$str = str_replace($search_str['find'], $search_str['replace'], $str);
		unset($search_str);
		$search_reg = array(
			'find'    => array('/([\\\'|"])(css|images|js|flash|xml)\\//', '/\\{template\\s+(.+?)\\}/ies', '/\\{include\\s+(.+)\\}/', '/\\{\\$(\\w+)\\.(\\w+)\\.(\\w+)\\}/', '/\\{\\$(\\w+)\\.(\\w+)\\}/', '/\\{:(.+?)\\}/', '/\\{php\\s+(.+)\\}/', '/\\{if\\s+(.+?)\\}/', '/\\{elseif\\s+(.+?)\\}/', '/\\{else\\}/', '/\\{\\/if\\}/', '/\\{for\\s+(.+?)\\}/', '/\\{\\/for\\}/', '/\\{\\+\\+(.+?)\\}/', '/\\{\\-\\-(.+?)\\}/', '/\\{(.+?)\\+\\+\\}/', '/\\{(.+?)\\-\\-\\}/', '/\\{loop\\s+(\\S+)\\s+(\\S+)\\}/', '/\\{loop\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)\\}/', '/\\{\\/loop\\}/', "/\\{([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff:]*\\(([^{}]*)\\))\\}/", "/\\{\\\$([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff:]*\\(([^{}]*)\\))\\}/", "/\\{(\\\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)\\}/", "/\\{(\\\$[a-zA-Z0-9_\\[\\]\\'\"\$\x7f-\xff]+)\\}/es", "/\\{([A-Z_\x7f-\xff][A-Z0-9_\x7f-\xff]*)\\}/s", '/\\{yp:(\\w+)\\s+([^}]+)\\}/ies', '/\\{\\/yp\\}/ie'),
			'replace' => array('\\1' . $tpl_path . '\\2/', 'self::YourphpTemplate(\'$1\')', '<?php include \\1; ?>', '<?php echo $\\1[\'\\2\'][\'\\3\'];?>', '<?php echo $\\1[\'\\2\'];?>', '<?php echo \\1;?>', '<?php \\1?>', '<?php if(\\1) { ?>', '<?php } elseif (\\1) { ?>', '<?php } else { ?>', '<?php } ?>', '<?php for(\\1) { ?>', '<?php } ?>', '<?php ++\\1; ?>', '<?php ++\\1; ?>', '<?php \\1++; ?>', '<?php \\1--; ?>', '<?php $n=1;if(is_array(\\1)) foreach(\\1 AS \\2) { ?>', '<?php $n=1; if(is_array(\\1)) foreach(\\1 AS \\2 => \\3) { ?>', '<?php $n++;}unset($n); ?>', '<?php echo \\1;?>', '<?php echo \\1;?>', '<?php echo \\1;?>', '$this->addquote(\'<?php echo \\1;?>\');', '<?php echo \\1;?>', 'self::YourphpTag(\'$1\',\'$2\', \'$0\')', 'self::end_tag()')
			);
		return preg_replace($search_reg['find'], $search_reg['replace'], $str);
	}

	public function addquote($var)
	{
		return str_replace('\\"', '"', preg_replace("/\\[([a-zA-Z0-9_\\-\\.\x7f-\xff]+)\\]/s", '[\'\\1\']', $var));
	}

	public function YourphpTemplate($attr)
	{
		$attr = stripslashes($attr);
		$data = explode('/', $attr);
		$leve = count($data);

		if ($leve == 2) {
			$Tpl = YOURPHP_PATH . 'Template/' . THEME_NAME . '/' . ($data[0] == 'Home' ? '' : $data[0] . '/') . $data[1] . '.html';

			if (GROUP_NAME != $data[0]) {
				$tpl_path = TMPL_PATH . THEME_NAME . '/' . ($data[0] == 'Home' ? '' : $data[0] . '/');
			}
		}
		else {
			$Tpl = THEME_PATH . $data[0] . '.html';
		}

		$html = file_get_contents($Tpl);
		return $this->parse($html, $tpl_path);
	}

	public function YourphpTag($op, $data, $html)
	{
		preg_match_all('/([a-z]+)\\=["]?([^"]+)["]?/i', stripslashes($data), $matches, PREG_SET_ORDER);
		$action = array(
			'list'   => array('attr' => 'm,urlmod,field,limit,order,catid,thumb,posid,where,page,status,urlrule,num,pagesize,start,return'),
			'get'    => array('attr' => 'sql,start,order,num,page,db,urlrule,return'),
			'xml'    => array('attr' => 'url,return'),
			'json'   => array('attr' => 'url,return'),
			'nav'    => array('attr' => 'catid,js,bcid,level,id,class,home,enhome,return', 'close' => 1),
			'catpos' => array('attr' => 'catid,space,return', 'close' => 1),
			'subcat' => array('attr' => 'catid,type,self,ismenu,return'),
			'kefu'   => array('attr' => 'position,right,close,effect,open,showopen,left,top,id,class,skin,return', 'close' => 1),
			'tags'   => array('attr' => 'keywords,list,field,key,mod,moduleid,limit,order,return'),
			'block'  => array('attr' => 'blockid,pos,return', 'close' => 1),
			'flash'  => array('attr' => 'flashid,return', 'close' => 1),
			'pre'    => array('attr' => 'return'),
			'next'   => array('attr' => 'return')
			);

		foreach ($matches as $v) {
			if (in_array($v[1], explode(',', $action[$op]['attr']))) {
				$tags[$v[1]] = $v[2];
			}
		}

		$tags['return'] = isset($tags['return']) && trim($tags['return']) ? trim($tags['return']) : 'data';

		if ($action[$op]) {
			$op = 'Yourphp' . ucwords($op);
			return $this->$op($tags, '');
		}
	}

	public function end_tag()
	{
		return '';
	}

	public function YourphpSubcat($tags, $html)
	{
		extract($tags, EXTR_OVERWRITE);
		$return = (isset($return) ? $return : 'data');
		$type = (isset($type) ? $type : 0);
		$self = (isset($self) ? 1 : 0);
		$ismenu = (isset($ismenu) ? $ismenu : 1);
		$catid = (isset($catid) ? $catid : 0);
		return '<?php $' . $return . '=subcat($Categorys,' . $catid . ',' . $type . ',' . $self . ',' . $ismenu . ');?>';
	}

	public function YourphpTags($tags, $html)
	{
		extract($tags, EXTR_OVERWRITE);
		$return = (isset($return) ? $return : 'data');
		$limit = (isset($tag['limit']) ? $tag['limit'] : '12');
		$order = (isset($tag['order']) ? $tag['order'] : 'id desc');
		$keywords = (!empty($tag['keywords']) ? $tag['keywords'] : '');
		$list = (!empty($tag['list']) ? $tag['list'] : '');
		if ($moduleid && !is_numeric($moduleid)) {
			if (substr($moduleid, 0, 2) == '$T[') {
				$T = $this->get('T');
				preg_match_all('/T\\[(\\\'?)(\\w*)(\\\'?)\\]$/', $blockid, $arr);
				$moduleid = $T[$arr[2][0]];
			}
			else {
				$moduleid = $this->get(substr($moduleid, 1));
			}
		}

		preg_match('/[a-zA-Z]+/', $keywords, $keywordsa);

		if ($keywordsa[0]) {
			$keywords = $this->get($keywords);
		}

		if ($keywords) {
			$keyarr = explode(',', $keywords);
			$keywords = '\'' . implode('\',\'', $keyarr) . '\'';
		}

		$where = (APP_LANG ? ' lang=' . LANG_ID : ' 1 ');
		$where .= ($keywords ? ' and name in(' . $keywords . ')' : '');

		if ($list) {
			$tagids = m('Tags')->where($where)->order($order)->limit($limit)->select();
			$where = ' b.status=1 ';

			if ($tagids[0]) {
				foreach ((array) $tagids as $r) {
					$tagidarr[] = $r['id'];
				}

				$tagid = implode(',', $tagidarr);
				$where .= ' and a.tagid in(' . $tagid . ')';
			}

			$where .= ($moduleid ? ' and a.moduleid=' . $moduleid : '');
			$prefix = c('DB_PREFIX');
			$mtable = $prefix . 'content';
			$field = ($field ? $field : 'b.id,b.catid,b.userid,b.url,b.username,b.title,b.keywords,b.description,b.thumb,b.createtime,b.hits');
			$table = $prefix . 'tags_data as a';
			$mtable = $mtable . ' as b on a.id=b.id';
			$sql = 'M("Tags_data")->field("' . $field . '")->table("' . $table . '")->join("' . $mtable . '")->where("' . $where . '")->order("' . $order . '")->group("b.id")->limit("' . $limit . '")->select();';
		}
		else {
			$sql = 'M("Tags")->where("' . $where . '")->order("' . $order . '")->limit("' . $limit . '")->select();';
		}

		return '<?php $' . $return . '=' . $sql . ';?>';
	}

	public function YourphpFlash($tags, $html)
	{
		extract($tags, EXTR_OVERWRITE);

		if (!$flashid) {
			return '';
		}

		if (APP_LANG) {
			$wherelang = ' and lang=' . $this->get('langid');
		}

		$flash = m('Slide')->where('status=1 and  id=' . $flashid)->find();

		if (empty($flash)) {
			return '';
		}

		$limit = ($flash['num'] ? $flash['num'] : 5);
		$str .= '$flash = M(\'Slide\')->where("status=1 and  id=' . $flashid . '")->find();$flashid=$flash[\'id\'];';
		$str .= '$' . $return . '=M(\'Slide_data\')->where("status=1 and  fid=' . $flashid . $wherelang . '")->order("listorder ASC ,id DESC")->limit(' . $limit . ')->select();';
		$Tpl = YOURPHP_PATH . 'Template/' . THEME_NAME . '/Slide_' . $flash['tpl'] . '.html';
		$html = file_get_contents($Tpl);
		$html = $this->parse($html);
		return '<?php ' . $str . ';?>' . $html;
	}

	public function YourphpCatpos($tags, $html)
	{
		extract($tags, EXTR_OVERWRITE);
		$parsestr = '';
		$parsestr .= '<?php  $arrparentid = array_filter(explode(\',\', $Categorys[' . $catid . '][\'arrparentid\'].\',\'.$catid));';
		$parsestr .= 'foreach($arrparentid as $cid):';
		$parsestr .= '$parsestr[] = \'<a href="\'.$Categorys[$cid][\'url\'].\'">\'.$Categorys[$cid][\'catname\'].\'</a>\';?>';
		$parsestr .= '<?php endforeach;echo implode("' . $space . '",$parsestr);?>';
		return $parsestr;
	}

	public function YourphpNav($tags, $html)
	{
		extract($tags, EXTR_OVERWRITE);
		require_cache(YOURPHP_CORE . 'Ext/Tree.class.php');
		$category_arr = $this->get('Categorys');
		$parsestr = '';
		if ($catid && !is_numeric($catid)) {
			if (substr($catid, 0, 3) == '$T[') {
				$T = $this->get('T');
				preg_match_all('/T\\[(\\\'?)(\\w*)(\\\'?)\\]$/', $catid, $arr);
				$catid = $T[$arr[2][0]];
			}
			else {
				$catid = $this->get(substr($catid, 1));
			}
		}

		if (is_array($category_arr)) {
			foreach ($category_arr as $r) {
				if (empty($r['ismenu'])) {
					continue;
				}

				$r['name'] = $r['catname'];
				$r['level'] = count(explode(',', $r['arrparentid']));
				$array[] = $r;
			}

			$tree = new Tree($array);
			unset($array);
			$parsestr = $tree->get_nav($catid, $level, $id, $class, $home, false, '', $enhome, $lang);
		}

		unset($tree);

		if (empty($js)) {
			$parsestr = $parsestr . '<script>$(\'#nav\').YourphpNav({ id: <?php echo $bcid;?>});</script>';
		}

		unset($category_arr);
		return $parsestr;
	}

	public function YourphpBlock($tags, $html)
	{
		extract($tags, EXTR_OVERWRITE);
		$where = '1 ';

		if (APP_LANG) {
			$where .= ' and lang=' . $this->get('langid');
		}

		if ($pos) {
			$where .= ' and pos=\'' . $pos . '\' ';
		}

		if ($blockid) {
			$where .= ' and id=\'' . $blockid . '\' ';
		}

		$r = m('Block')->where($where)->find();
		return $r['content'];
	}

	public function YourphpPre($tags, $html)
	{
		extract($tags, EXTR_OVERWRITE);
		$langwhere = (APP_LANG ? ' and lang=' . $this->get('langid') : '');
		$return = (isset($return) ? $return : 'data');
		return '<?php $' . $return . ' = M("Content")->where("catid=$catid and id<$id ' . $langwhere . '")->order("id DESC")->find();?>';
	}

	public function YourphpNext($tags, $html)
	{
		extract($tags, EXTR_OVERWRITE);
		$langwhere = (APP_LANG ? ' and lang=' . $this->get('langid') : '');
		$return = (isset($return) ? $return : 'data');
		return '<?php $' . $return . ' = M("Content")->where("catid=$catid and id>$id ' . $langwhere . '")->order("id ASC")->find();?>';
	}

	public function YourphpJson($tags, $html)
	{
		extract($tags, EXTR_OVERWRITE);
		$return = (isset($return) ? $return : 'data');
		if (isset($url) && !empty($url)) {
			$str .= '$json = @file_get_contents(\'' . $url . '\');';
			$str .= '$' . $return . ' = json_decode($json, true);';
		}

		return '<?php ' . $str . ';?>';
	}

	public function YourphpXml($tags, $html)
	{
		extract($tags, EXTR_OVERWRITE);
		$return = (isset($return) ? $return : 'data');
		$str .= 'import("@.EXT.Xml");$xml =new xml();';
		$str .= '$xml_data = @file_get_contents(\'' . $url . '\');';
		$str .= '$' . $return . ' = $xml->xml_unserialize($xml_data);';
		return '<?php ' . $str . ';?>';
	}

	public function YourphpKefu($tags, $html)
	{
		extract($tags, EXTR_OVERWRITE);
		$order = (isset($order) ? $order : 'listorder desc ,id desc');
		$top = (isset($top) ? $top : '100');
		$position = (isset($position) ? $position : 'right');
		$left = (isset($left) ? $left : 0);
		$right = (isset($right) ? $right : 0);
		$close = (isset($close) ? $close : 0);
		$effect = (isset($effect) ? $effect : 1);
		$open = (isset($open) ? $open : 1);
		$showopen = (isset($showopen) ? $showopen : 1);
		$skindir = (isset($skin) ? $skin : 'default');
		$where = 'status=1';

		if (APP_LANG) {
			$where .= ' and lang=' . $this->get('langid');
		}

		if ($type) {
			$where .= ' and type in(' . $type . ')';
		}

		$data = m('Kefu')->field('*')->where($where)->order($order)->select();

		if (empty($data)) {
			return '';
		}

		$site_name = $this->get('site_name');

		foreach ($data as $key => $r) {
			if ($r['name']) {
				$datas .= '<li class="tit type_' . $r['type'] . '">' . $r['name'] . ':</li>';
			}

			if ($r['type'] == 1) {
				$skin = str_replace('q', '', $r['skin']);
				$codes = explode("\n", $r['code']);

				foreach ((array) $codes as $code) {
					if ($code) {
						$codearr = explode('|', $code);
						$code = $codearr[0];
						$codename = $codearr[1];
						$datas .= '<li><a href="http://wpa.qq.com/msgrd?v=3&uin=' . $code . '&site=qq&menu=yes" rel="nofollow"><img border="0" SRC="http://wpa.qq.com/pa?p=1:' . $code . ':' . $skin . '" alt="' . $r['name'] . '">' . $codename . '</a></li>';
					}
				}
			}
			else if ($r['type'] == 2) {
				$skin = str_replace('m', '', $r['skin']);
				$codes = explode("\n", $r['code']);

				foreach ((array) $codes as $code) {
					if ($code) {
						$codearr = explode('|', $code);
						$code = $codearr[0];
						$codename = $codearr[1];
						$datas .= '<li><a href="msnim:chat?contact=' . $code . '"><img src="' . YP_PUB . '/Images/kefu/msn' . $skin . '.gif">' . $codename . '</a></li>';
					}
				}
			}
			else if ($r['type'] == 3) {
				$skin = str_replace('w', '', $r['skin']);
				$codes = explode("\n", $r['code']);

				foreach ((array) $codes as $code) {
					if ($code) {
						$codearr = explode('|', $code);
						$code = $codearr[0];
						$codename = $codearr[1];
						$datas .= '<li><a target="_blank" href="http://www.taobao.com/webww/ww.php?ver=3&touid=' . $code . '&siteid=cntaobao&status=' . $skin . '&charset=utf-8" rel="nofollow"><img border="0" src="http://amos.alicdn.com/online.aw?v=2&uid=' . $code . '&site=cntaobao&s=' . $skin . '&charset=utf-8" alt="' . $r['name'] . '" />' . $codename . '</a></li>';
					}
				}
			}
			else if ($r['type'] == 4) {
				$codes = explode("\n", $r['code']);

				foreach ((array) $codes as $code) {
					if ($code) {
						$codearr = explode('|', $code);
						$code = $codearr[0];
						$codename = $codearr[1];

						if ($codename) {
							$codename = '<label>' . $codename . '</label>';
						}

						$datas .= '<li>' . $codename . $code . '</li>';
					}
				}
			}
			else if ($r['type'] == 5) {
				$datas .= '<li>' . stripcslashes($r['code']) . '</li>';
			}
			else if ($r['type'] == 6) {
				$skin = str_replace('al', '', $r['skin']);
				$codes = explode("\n", $r['code']);

				foreach ((array) $codes as $code) {
					if ($code) {
						$codearr = explode('|', $code);
						$code = $codearr[0];
						$codename = $codearr[1];
						$datas .= '<a href="http://web.im.alisoft.com/msg.aw?v=2&uid=' . $code . '&site=cnalichn&s=1" target="_blank"><img alt="' . $r['name'] . '" src="http://web.im.alisoft.com/online.aw?v=2&uid=' . $code . '&site=cnalichn&s=' . $skin . '" border="0" />' . $codename . '</a>';
					}
				}
			}
			else {
				$datas .= '<li>' . $r['code'] . '</li>';
			}
		}

		$parsestr = '';
		$parsestr .= '<div class="kefu" id="' . $id . '"><div class="open"></div><div class="kefubox"><div class="kftop"><div class="close"></div></div><div class="kfbox"><ul>';
		$parsestr .= $datas;
		$parsestr .= '</ul></div><div class="kfbottom"></div></div></div>';
		$parsestr .= '<script>$.YourphpInc("' . GROUP_TMPL_PATH . 'images/kefu/' . $skindir . '/style.css");$(document).ready(function(){  $("#' . $id . '").YourphpKefu({ top:200,position:"' . $position . '",left:' . $left . ',right:' . $right . ',close:' . $close . ',effect:' . $effect . ',open:' . $open . ',showopen:' . $showopen . ' }); });</script>';
		return $parsestr;
	}

	public function YourphpGet($tags, $html)
	{
		extract($tags, EXTR_OVERWRITE);
		$return = (isset($return) ? $return : 'data');
		$sql = (isset($sql) ? $sql : '');

		if (isset($db)) {
			$dbsql = '';
			$dbsource = f('Dbsource');
			$db = $dbsource[$db];

			if ($db) {
				$sql = str_replace('{tablepre}', $db['dbtablepre'], $sql);
				$db = 'mysql://' . $db['username'] . ':' . $db['password'] . '@' . $db['host'] . ':' . $db['port'] . '/' . $db['dbname'];
				$dbsql = 'db(1,"' . $db . '")->';
			}
		}

		if ($urlmod && !$urlrule) {
			unset($_GET['catdir']);
			$getrule = $_GET;
			unset($getrule['p']);
			$urlrule = YP_PATH . '/index.php?' . http_build_query($getrule) . '|' . YP_PATH . '/index.php?' . http_build_query($getrule) . '&p={$p}';
		}

		$listRows = (isset($num) ? $num : c('PAGE_LISTROWS'));

		if (isset($page)) {
			$str .= 'C(\'CREATE_LISTROWS\',' . $listRows . ');';

			if ($countsql = preg_replace('/select([^from].*)from/i', 'SELECT COUNT(*) as count FROM ', $sql)) {
				$str .= '$total=M()->' . $dbsql . 'query("' . $countsql . '");$total=$total[0][count];';
				$str .= 'import ( "@.EXT.Page" );$page = new Page ( $total, ' . $listRows . ' );';

				if ($urlrule) {
					$str .= '$page->urlrule = \'' . $urlrule . '\';';
				}

				$str .= '$pages = $page->show();';
			}

			$limit = '$page->firstRow,$page->listRows';
		}
		else {
			$limit = (isset($start) ? $start . ',' . $listRows : $listRows);
		}

		$str .= '$' . $return . '=M()->' . $dbsql . 'query("' . $sql . ' limit ' . $limit . '");';
		return '<?php ' . $str . ';?>';
	}

	public function YourphpList($tags, $html)
	{
		extract($tags, EXTR_OVERWRITE);
		$return = (isset($return) ? $return : 'data');
		$field = (isset($field) ? $field : '*');
		$sqlwhere = (isset($where) ? ' AND ' . $where : '');
		$start = (isset($start) ? $start : 0);
		$ids = (isset($ids) ? $ids : '');
		$listRows = (isset($num) ? $num : c('PAGE_LISTROWS'));

		if (empty($m)) {
			$m = 'Content';
			$alias = $where = '';
		}
		else {
			$mod = c('M');

			if ($mod[$m]) {
				$alias = 'a.';
				$where = ' a.id=b.id AND ';
			}
			else {
				$where = '';
			}
		}

		$order = (isset($order) ? $order : ' ' . $alias . 'id DESC ');
		$str = $morewhere = '';

		if (isset($catid)) {
			$str .= '$catsql = getcatsql(' . $catid . ',\'' . $alias . '\');';
		}

		$where .= (!isset($status) ? ' ' . $alias . 'status=1 ' : ' ' . $alias . 'status=' . $status . ' ');
		$where .= (APP_LANG ? ' AND ' . $alias . 'lang=' . $this->get('langid') : '');

		if (isset($posid)) {
			if (is_numeric($posid)) {
				$morewhere .= '  AND ' . $alias . 'posid =' . $posid;
			}
			else {
				$morewhere .= ' AND ' . $alias . 'posid in(' . $posid . ')';
			}
		}

		$morewhere .= ($thumb ? ' AND  ' . $alias . 'thumb <>\'\' ' : '');

		if ($urlmod) {
			unset($_GET['catdir']);
			$getrule = $_GET;
			unset($getrule['p']);
			$urlrule = YP_PATH . '/index.php?' . http_build_query($getrule) . '|' . YP_PATH . '/index.php?' . http_build_query($getrule) . '&p={$p}';
		}

		if (isset($page)) {
			$str .= 'C(\'CREATE_LISTROWS\',' . $listRows . ');';
			$str .= 'if(C(\'CREATE_TOTAL\')){$total=C(\'CREATE_TOTAL\');}else{$total=M("' . $m . '")->where("' . $where . ' $catsql[sql] ' . $morewhere . ' ' . $sqlwhere . ' ")->count();C(\'CREATE_TOTAL\',$total);}';
			$str .= 'import ( "@.EXT.Page" );$page = new Page ( $total, ' . $listRows . ' );';
			if (isset($catid) && !$urlrule) {
				$str .= 'if($catsql[\'urlrule\'])$page->urlrule =$catsql[\'urlrule\'];';
			}

			if ($urlrule) {
				$str .= '$page->urlrule = \'' . $urlrule . '\';';
			}

			$str .= '$pages = $page->show();';
			$limit = '$page->firstRow . \',\' . $page->listRows';
		}
		else {
			$limit = (isset($start) ? $start . ',' . $listRows : $listRows);
		}

		$str .= 'unset($' . $return . ');$' . $return . '=M("' . $m . '")->field("' . $field . '")->where("' . $where . ' $catsql[sql]  ' . $morewhere . ' ' . $sqlwhere . '")->order("' . $order . '")->limit(' . $limit . ')->select();';

		if (isset($catid)) {
			$str .= 'unset($catsql);';
		}

		return '<?php ' . $str . ';?>';
	}

	protected function checkCache($tmplTemplateFile, $prefix = '')
	{
		if (!is_file($this->templCacheFile)) {
			return false;
		}
		else if (filemtime($this->templCacheFile) < filemtime($tmplTemplateFile)) {
			return false;
		}
		else {
			if (($this->config['cache_time'] != 0) && ((filemtime($this->templCacheFile) + $this->config['cache_time']) < time())) {
				return false;
			}
		}

		if ($this->config['layout_no']) {
			$layoutFile = THEME_PATH . $this->config['layout_name'] . $this->config['template_suffix'];

			if (filemtime($this->templCacheFile) < filemtime($layoutFile)) {
				return false;
			}
		}

		return true;
	}
}

class Model
{
	const MODEL_INSERT = 1;
	const MODEL_UPDATE = 2;
	const MODEL_BOTH = 3;
	const MUST_VALIDATE = 1;
	const EXISTS_VALIDATE = 0;
	const VALUE_VALIDATE = 2;

	private $_extModel;
	protected $db;
	protected $pk = 'id';
	protected $tablePrefix = '';
	protected $name = '';
	protected $dbName = '';
	protected $connection = '';
	protected $tableName = '';
	protected $trueTableName = '';
	protected $error = '';
	protected $fields = array();
	protected $data = array();
	protected $options = array();
	protected $_validate = array();
	protected $_auto = array();
	protected $_map = array();
	protected $_scope = array();
	protected $autoCheckFields = true;
	protected $patchValidate = false;
	protected $methods = array('table', 'order', 'alias', 'having', 'group', 'lock', 'distinct', 'auto', 'filter', 'validate');

	public function __construct($name = '', $tablePrefix = '', $connection = '')
	{
		$this->_initialize();

		if (!empty($name)) {
			if (strpos($name, '.')) {
				list($this->dbName, $this->name) = explode('.', $name);
			}
			else {
				$this->name = $name;
			}
		}
		else if (empty($this->name)) {
			$this->name = $this->getModelName();
		}

		if (is_null($tablePrefix)) {
			$this->tablePrefix = '';
		}
		else if ('' != $tablePrefix) {
			$this->tablePrefix = $tablePrefix;
		}
		else {
			$this->tablePrefix = $this->tablePrefix ? $this->tablePrefix : C('DB_PREFIX');
		}
		$this->db(0, empty($this->connection) ? $connection : $this->connection);
	}

	protected function _checkTableInfo()
	{
		if (empty($this->fields)) {
			if (c('DB_FIELDS_CACHE')) {
				$db = ($this->dbName ? $this->dbName : c('DB_NAME'));
				$fields = f('_fields/' . strtolower($db . '.' . $this->name));

				if ($fields) {
					$version = c('DB_FIELD_VERISON');
					if (empty($version) || ($fields['_version'] == $version)) {
						$this->fields = $fields;
						return NULL;
					}
				}
			}

			$this->flush();
		}
	}

	public function flush()
	{
		$this->db->setModel($this->name);
		$fields = $this->db->getFields($this->getTableName());

		if (!$fields) {
			return false;
		}

		$this->fields = array_keys($fields);
		$this->fields['_autoinc'] = false;

		foreach ($fields as $key => $val) {
			$type[$key] = $val['type'];

			if ($val['primary']) {
				$this->fields['_pk'] = $key;

				if ($val['autoinc']) {
					$this->fields['_autoinc'] = true;
				}
			}
		}

		$this->fields['_type'] = $type;

		if (c('DB_FIELD_VERISON')) {
			$this->fields['_version'] = c('DB_FIELD_VERISON');
		}

		if (c('DB_FIELDS_CACHE')) {
			$db = ($this->dbName ? $this->dbName : c('DB_NAME'));
			f('_fields/' . strtolower($db . '.' . $this->name), $this->fields);
		}
	}

	public function switchModel($type, $vars = array())
	{
		$class = ucwords(strtolower($type)) . 'Model';

		if (!class_exists($class)) {
			throw_exception($class . l('_MODEL_NOT_EXIST_'));
		}

		$this->_extModel = new $class($this->name);

		if (!empty($vars)) {
			foreach ($vars as $var) {
				$this->_extModel->setProperty($var, $this->$var);
			}
		}

		return $this->_extModel;
	}

	public function __set($name, $value)
	{
		$this->data[$name] = $value;
	}

	public function __get($name)
	{
		return isset($this->data[$name]) ? $this->data[$name] : NULL;
	}

	public function __isset($name)
	{
		return isset($this->data[$name]);
	}

	public function __unset($name)
	{
		unset($this->data[$name]);
	}

	public function __call($method, $args)
	{
		if (in_array(strtolower($method), $this->methods, true)) {
			$this->options[strtolower($method)] = $args[0];
			return $this;
		}
		else if (in_array(strtolower($method), array('count', 'sum', 'min', 'max', 'avg'), true)) {
			$field = (isset($args[0]) ? $args[0] : '*');
			return $this->getField(strtoupper($method) . '(' . $field . ') AS tp_' . $method);
		}
		else if (strtolower(substr($method, 0, 5)) == 'getby') {
			$field = parse_name(substr($method, 5));
			$where[$field] = $args[0];
			return $this->where($where)->find();
		}
		else if (strtolower(substr($method, 0, 10)) == 'getfieldby') {
			$name = parse_name(substr($method, 10));
			$where[$name] = $args[0];
			return $this->where($where)->getField($args[1]);
		}
		else if (isset($this->_scope[$method])) {
			return $this->scope($method, $args[0]);
		}
		else {
			throw_exception('Model' . ':' . $method . l('_METHOD_NOT_EXIST_'));
			return NULL;
		}
	}

	protected function _initialize()
	{
	}

	protected function _facade($data)
	{
		if (!empty($this->fields)) {
			foreach ($data as $key => $val) {
				if (!in_array($key, $this->fields, true)) {
					unset($data[$key]);
				}
				else if (is_scalar($val)) {
					$this->_parseType($data, $key);
				}
			}
		}

		if (!empty($this->options['filter'])) {
			$data = array_map($this->options['filter'], $data);
			unset($this->options['filter']);
		}

		$this->_before_write($data);
		return $data;
	}

	protected function _before_write(&$data)
	{
	}

	public function add($data = '', $options = array(), $replace = false)
	{
		if (empty($data)) {
			if (!empty($this->data)) {
				$data = $this->data;
				$this->data = array();
			}
			else {
				$this->error = l('_DATA_TYPE_INVALID_');
				return false;
			}
		}

		$options = $this->_parseOptions($options);
		$data = $this->_facade($data);

		if (false === $this->_before_insert($data, $options)) {
			return false;
		}

		$result = $this->db->insert($data, $options, $replace);

		if (false !== $result) {
			$insertId = $this->getLastInsID();

			if ($insertId) {
				$data[$this->getPk()] = $insertId;
				$this->_after_insert($data, $options);
				return $insertId;
			}

			$this->_after_insert($data, $options);
		}

		return $result;
	}

	protected function _before_insert(&$data, $options)
	{
	}

	protected function _after_insert($data, $options)
	{
	}

	public function addAll($dataList, $options = array(), $replace = false)
	{
		if (empty($dataList)) {
			$this->error = l('_DATA_TYPE_INVALID_');
			return false;
		}

		$options = $this->_parseOptions($options);

		foreach ($dataList as $key => $data) {
			$dataList[$key] = $this->_facade($data);
		}

		$result = $this->db->insertAll($dataList, $options, $replace);

		if (false !== $result) {
			$insertId = $this->getLastInsID();

			if ($insertId) {
				return $insertId;
			}
		}

		return $result;
	}

	public function selectAdd($fields = '', $table = '', $options = array())
	{
		$options = $this->_parseOptions($options);
		if (false === $result = $this->db->selectInsert($fields ? $fields : $options['field'], $table ? $table : $this->getTableName(), $options)) {
			$this->error = l('_OPERATION_WRONG_');
			return false;
		}
		else {
			return $result;
		}
	}

	public function save($data = '', $options = array())
	{
		if (empty($data)) {
			if (!empty($this->data)) {
				$data = $this->data;
				$this->data = array();
			}
			else {
				$this->error = l('_DATA_TYPE_INVALID_');
				return false;
			}
		}

		$data = $this->_facade($data);
		$options = $this->_parseOptions($options);

		if (false === $this->_before_update($data, $options)) {
			return false;
		}

		if (!isset($options['where'])) {
			if (isset($data[$this->getPk()])) {
				$pk = $this->getPk();
				$where[$pk] = $data[$pk];
				$options['where'] = $where;
				$pkValue = $data[$pk];
				unset($data[$pk]);
			}
			else {
				$this->error = l('_OPERATION_WRONG_');
				return false;
			}
		}

		$result = $this->db->update($data, $options);

		if (false !== $result) {
			if (isset($pkValue)) {
				$data[$pk] = $pkValue;
			}

			$this->_after_update($data, $options);
		}

		return $result;
	}

	protected function _before_update(&$data, $options)
	{
	}

	protected function _after_update($data, $options)
	{
	}

	public function delete($options = array())
	{
		if (empty($options) && empty($this->options['where'])) {
			if (!empty($this->data) && isset($this->data[$this->getPk()])) {
				return $this->delete($this->data[$this->getPk()]);
			}
			else {
				return false;
			}
		}

		if (is_numeric($options) || is_string($options)) {
			$pk = $this->getPk();

			if (strpos($options, ',')) {
				$where[$pk] = array('IN', $options);
			}
			else {
				$where[$pk] = $options;
			}

			$pkValue = $where[$pk];
			$options = array();
			$options['where'] = $where;
		}

		$options = $this->_parseOptions($options);
		$result = $this->db->delete($options);

		if (false !== $result) {
			$data = array();

			if (isset($pkValue)) {
				$data[$pk] = $pkValue;
			}

			$this->_after_delete($data, $options);
		}

		return $result;
	}

	protected function _after_delete($data, $options)
	{
	}

	public function select($options = array())
	{
		if (is_string($options) || is_numeric($options)) {
			$pk = $this->getPk();
			$M = c('M');

			if ($M[$this->name]) {
				$pk = 'a.' . $pk;
				$where[$pk] = 'b.id';

				if (strpos($options, ',')) {
					$where = 'a.id=b.id and a.id in(' . $options . ')';
				}
				else {
					$where = 'a.id=b.id and a.id =\'' . $options . '\'';
				}
			}
			else if (strpos($options, ',')) {
				$where[$pk] = array('IN', $options);
			}
			else {
				$where[$pk] = $options;
			}

			$options = array();
			$options['where'] = $where;
		}
		else if (false === $options) {
			$options = array();
			$options = $this->_parseOptions($options);
			return '( ' . $this->db->buildSelectSql($options) . ' )';
		}

		$options = $this->_parseOptions($options);
		$resultSet = $this->db->select($options);

		if (false === $resultSet) {
			return false;
		}

		if (empty($resultSet)) {
			return NULL;
		}

		$this->_after_select($resultSet, $options);
		return $resultSet;
	}

	protected function _after_select(&$resultSet, $options)
	{
	}

	public function buildSql($options = array())
	{
		$options = $this->_parseOptions($options);
		return '( ' . $this->db->buildSelectSql($options) . ' )';
	}

	protected function _parseOptions($options = array())
	{
		if (is_array($options)) {
			$options = array_merge($this->options, $options);
		}

		$this->options = array();

		if (!isset($options['table'])) {
			$options['table'] = $this->getTableName();
			$fields = $this->fields;
		}
		else {
			$fields = $this->getDbFields();
		}

		if (!empty($options['alias'])) {
			$options['table'] .= ' ' . $options['alias'];
		}

		$options['model'] = $this->name;
		if (isset($options['where']) && is_array($options['where']) && !empty($fields)) {
			foreach ($options['where'] as $key => $val) {
				$key = trim($key);

				if (in_array($key, $fields, true)) {
					if (is_scalar($val)) {
						$this->_parseType($options['where'], $key);
					}
				}
				else {
					if (('_' != substr($key, 0, 1)) && (false === strpos($key, '.')) && (false === strpos($key, '|')) && (false === strpos($key, '&'))) {
						unset($options['where'][$key]);
					}
				}
			}
		}

		$this->_options_filter($options);
		return $options;
	}

	protected function _options_filter(&$options)
	{
	}

	protected function _parseType(&$data, $key)
	{
		$fieldType = strtolower($this->fields['_type'][$key]);
		if ((false === strpos($fieldType, 'bigint')) && (false !== strpos($fieldType, 'int'))) {
			$data[$key] = intval($data[$key]);
		}
		else {
			if ((false !== strpos($fieldType, 'float')) || (false !== strpos($fieldType, 'double'))) {
				$data[$key] = floatval($data[$key]);
			}
			else if (false !== strpos($fieldType, 'bool')) {
				$data[$key] = (bool) $data[$key];
			}
		}
	}

	public function find($options = array())
	{
		if (is_numeric($options) || is_string($options)) {
			$pk = $this->getPk();
			$M = c('M');

			if ($M[$this->name]) {
				$pk = 'a.' . $pk;
				$where = ' a.id=b.id AND a.id=' . $options;
			}
			else {
				$where[$pk] = $options;
			}

			$options = array();
			$options['where'] = $where;
		}

		$options['limit'] = 1;
		$options = $this->_parseOptions($options);
		$resultSet = $this->db->select($options);

		if (false === $resultSet) {
			return false;
		}

		if (empty($resultSet)) {
			return NULL;
		}

		$this->data = $resultSet[0];
		$this->_after_find($this->data, $options);
		return $this->data;
	}

	protected function _after_find(&$result, $options)
	{
	}

	public function parseFieldsMap($data, $type = 1)
	{
		if (!empty($this->_map)) {
			foreach ($this->_map as $key => $val) {
				if ($type == 1) {
					if (isset($data[$val])) {
						$data[$key] = $data[$val];
						unset($data[$val]);
					}
				}
				else if (isset($data[$key])) {
					$data[$val] = $data[$key];
					unset($data[$key]);
				}
			}
		}

		return $data;
	}

	public function setField($field, $value = '')
	{
		if (is_array($field)) {
			$data = $field;
		}
		else {
			$data[$field] = $value;
		}

		return $this->save($data);
	}

	public function setInc($field, $step = 1)
	{
		return $this->setField($field, array('exp', $field . '+' . $step));
	}

	public function setDec($field, $step = 1)
	{
		return $this->setField($field, array('exp', $field . '-' . $step));
	}

	public function getField($field, $sepa = NULL)
	{
		$options['field'] = $field;
		$options = $this->_parseOptions($options);
		$field = trim($field);

		if (strpos($field, ',')) {
			if (!isset($options['limit'])) {
				$options['limit'] = is_numeric($sepa) ? $sepa : '';
			}

			$resultSet = $this->db->select($options);

			if (!empty($resultSet)) {
				$_field = explode(',', $field);
				$field = array_keys($resultSet[0]);
				$key = array_shift($field);
				$key2 = array_shift($field);
				$cols = array();
				$count = count($_field);

				foreach ($resultSet as $result) {
					$name = $result[$key];

					if (2 == $count) {
						$cols[$name] = $result[$key2];
					}
					else {
						$cols[$name] = is_string($sepa) ? implode($sepa, $result) : $result;
					}
				}

				return $cols;
			}
		}
		else {
			if (true !== $sepa) {
				$options['limit'] = is_numeric($sepa) ? $sepa : 1;
			}

			$result = $this->db->select($options);

			if (!empty($result)) {
				if ((true !== $sepa) && (1 == $options['limit'])) {
					return reset($result[0]);
				}

				foreach ($result as $val) {
					$array[] = $val[$field];
				}

				return $array;
			}
		}

		return NULL;
	}

	public function create($data = '', $type = '')
	{
		if (empty($data)) {
			$data = $_POST;
		}
		else if (is_object($data)) {
			$data = get_object_vars($data);
		}

		if (empty($data) || !is_array($data)) {
			$this->error = l('_DATA_TYPE_INVALID_');
			return false;
		}

		$data = $this->parseFieldsMap($data, 0);
		$type = ($type ? $type : (!empty($data[$this->getPk()]) ? self::MODEL_UPDATE : self::MODEL_INSERT));

		if (isset($this->options['field'])) {
			$fields = $this->options['field'];
			unset($this->options['field']);
		}
		else {
			if (($type == self::MODEL_INSERT) && isset($this->insertFields)) {
				$fields = $this->insertFields;
			}
			else {
				if (($type == self::MODEL_UPDATE) && isset($this->updateFields)) {
					$fields = $this->updateFields;
				}
			}
		}

		if (isset($fields)) {
			if (is_string($fields)) {
				$fields = explode(',', $fields);
			}

			if (c('TOKEN_ON')) {
				$fields[] = c('TOKEN_NAME');
			}

			foreach ($data as $key => $val) {
				if (!in_array($key, $fields)) {
					unset($data[$key]);
				}
			}
		}

		if (!$this->autoValidation($data, $type)) {
			return false;
		}

		if (c('TOKEN_ON') && !$this->autoCheckToken($data)) {
			$this->error = l('_TOKEN_ERROR_');
			return false;
		}

		if ($this->autoCheckFields) {
			$fields = $this->getDbFields();

			foreach ($data as $key => $val) {
				if (!in_array($key, $fields)) {
					unset($data[$key]);
				}
				else {
					if (MAGIC_QUOTES_GPC && is_string($val)) {
						$data[$key] = stripslashes($val);
					}
				}
			}
		}

		$this->autoOperation($data, $type);
		$this->data = $data;
		return $data;
	}

	public function autoCheckToken($data)
	{
		if (c('TOKEN_ON')) {
			$name = c('TOKEN_NAME');
			if (!isset($data[$name]) || !isset($_SESSION[$name])) {
				return false;
			}

			list($key, $value) = explode('_', $data[$name]);
			if ($value && ($_SESSION[$name][$key] === $value)) {
				unset($_SESSION[$name][$key]);
				return true;
			}

			if (c('TOKEN_RESET')) {
				unset($_SESSION[$name][$key]);
			}

			return false;
		}

		return true;
	}

	public function regex($value, $rule)
	{
		$validate = array('require' => '/.+/', 'email' => '/^\\w+([-+.]\\w+)*@\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*$/', 'url' => '/^http(s?):\\/\\/(?:[A-za-z0-9-]+\\.)+[A-za-z]{2,4}(?:[\\/\\?#][\\/=\\?%\\-&~`@[\\]\':+!\\.#\\w]*)?$/', 'currency' => '/^\\d+(\\.\\d+)?$/', 'number' => '/^\\d+$/', 'zip' => '/^\\d{6}$/', 'integer' => '/^[-\\+]?\\d+$/', 'double' => '/^[-\\+]?\\d+(\\.\\d+)?$/', 'english' => '/^[A-Za-z]+$/');

		if (isset($validate[strtolower($rule)])) {
			$rule = $validate[strtolower($rule)];
		}

		return preg_match($rule, $value) === 1;
	}

	private function autoOperation(&$data, $type)
	{
		if (!empty($this->options['auto'])) {
			$_auto = $this->options['auto'];
			unset($this->options['auto']);
		}
		else if (!empty($this->_auto)) {
			$_auto = $this->_auto;
		}

		if (isset($_auto)) {
			foreach ($_auto as $auto) {
				if (empty($auto[2])) {
					$auto[2] = self::MODEL_INSERT;
				}

				if (($type == $auto[2]) || ($auto[2] == self::MODEL_BOTH)) {
					switch (trim($auto[3])) {
					case 'function':
					case 'callback':
						$args = (isset($auto[4]) ? (array) $auto[4] : array());

						if (isset($data[$auto[0]])) {
							array_unshift($args, $data[$auto[0]]);
						}

						if ('function' == $auto[3]) {
							$data[$auto[0]] = call_user_func_array($auto[1], $args);
						}
						else {
							$data[$auto[0]] = call_user_func_array(array(&$this, $auto[1]), $args);
						}

						break;

					case 'field':
						$data[$auto[0]] = $data[$auto[1]];
						break;

					case 'ignore':
						if ('' === $data[$auto[0]]) {
							unset($data[$auto[0]]);
						}

						break;

					case 'string':
					default:
						$data[$auto[0]] = $auto[1];
					}

					if (false === $data[$auto[0]]) {
						unset($data[$auto[0]]);
					}
				}
			}
		}

		return $data;
	}

	protected function autoValidation($data, $type)
	{
		if (!empty($this->options['validate'])) {
			$_validate = $this->options['validate'];
			unset($this->options['validate']);
		}
		else if (!empty($this->_validate)) {
			$_validate = $this->_validate;
		}

		if (isset($_validate)) {
			if ($this->patchValidate) {
				$this->error = array();
			}

			foreach ($_validate as $key => $val) {
				if (empty($val[5]) || ($val[5] == self::MODEL_BOTH) || ($val[5] == $type)) {
					if ((0 == strpos($val[2], '{%')) && strpos($val[2], '}')) {
						$val[2] = l(substr($val[2], 2, -1));
					}

					$val[3] = isset($val[3]) ? $val[3] : self::EXISTS_VALIDATE;
					$val[4] = isset($val[4]) ? $val[4] : 'regex';

					switch ($val[3]) {
					case self::MUST_VALIDATE:
						if (false === $this->_validationField($data, $val)) {
							return false;
						}

						break;

					case self::VALUE_VALIDATE:
						if ('' != trim($data[$val[0]])) {
							if (false === $this->_validationField($data, $val)) {
								return false;
							}
						}

						break;

					default:
						if (isset($data[$val[0]])) {
							if (false === $this->_validationField($data, $val)) {
								return false;
							}
						}
					}
				}
			}

			if (!empty($this->error)) {
				return false;
			}
		}

		return true;
	}

	protected function _validationField($data, $val)
	{
		if (false === $this->_validationFieldItem($data, $val)) {
			if ($this->patchValidate) {
				$this->error[$val[0]] = $val[2];
			}
			else {
				$this->error = $val[2];
				return false;
			}
		}

		return NULL;
	}

	protected function _validationFieldItem($data, $val)
	{
		switch (strtolower(trim($val[4]))) {
		case 'function':
		case 'callback':
			$args = (isset($val[6]) ? (array) $val[6] : array());
			if (is_string($val[0]) && strpos($val[0], ',')) {
				$val[0] = explode(',', $val[0]);
			}

			if (is_array($val[0])) {
				foreach ($val[0] as $field) {
					$_data[$field] = $data[$field];
				}

				array_unshift($args, $_data);
			}
			else {
				array_unshift($args, $data[$val[0]]);
			}

			if ('function' == $val[4]) {
				return call_user_func_array($val[1], $args);
			}
			else {
				return call_user_func_array(array(&$this, $val[1]), $args);
			}
		case 'confirm':
			return $data[$val[0]] == $data[$val[1]];
		case 'unique':
			if (is_string($val[0]) && strpos($val[0], ',')) {
				$val[0] = explode(',', $val[0]);
			}

			$map = array();

			if (is_array($val[0])) {
				foreach ($val[0] as $field) {
					$map[$field] = $data[$field];
				}
			}
			else {
				$map[$val[0]] = $data[$val[0]];
			}

			if (!empty($data[$this->getPk()])) {
				$map[$this->getPk()] = array('neq', $data[$this->getPk()]);
			}

			if ($this->where($map)->find()) {
				return false;
			}

			return true;
		default:
			return $this->check($data[$val[0]], $val[1], $val[4]);
		}
	}

	public function check($value, $rule, $type = 'regex')
	{
		$type = strtolower(trim($type));

		switch ($type) {
		case 'in':
		case 'notin':
			$range = (is_array($rule) ? $rule : explode(',', $rule));
			return $type == 'in' ? in_array($value, $range) : !in_array($value, $range);
		case 'between':
		case 'notbetween':
			if (is_array($rule)) {
				$min = $rule[0];
				$max = $rule[1];
			}
			else {
				list($min, $max) = explode(',', $rule);
			}

			return $type == 'between' ? ($min <= $value) && ($value <= $max) : ($value < $min) || ($max < $value);
		case 'equal':
		case 'notequal':
			return $type == 'equal' ? $value == $rule : $value != $rule;
		case 'length':
			$length = mb_strlen($value, 'utf-8');

			if (strpos($rule, ',')) {
				list($min, $max) = explode(',', $rule);
				return ($min <= $length) && ($length <= $max);
			}
			else {
				return $length == $rule;
			}
		case 'expire':
			list($start, $end) = explode(',', $rule);

			if (!is_numeric($start)) {
				$start = strtotime($start);
			}

			if (!is_numeric($end)) {
				$end = strtotime($end);
			}

			return ($start <= NOW_TIME) && (NOW_TIME <= $end);
		case 'ip_allow':
			return in_array(ip(), explode(',', $rule));
		case 'ip_deny':
			return !in_array(ip(), explode(',', $rule));
		case 'regex':
		default:
			return $this->regex($value, $rule);
		}
	}

	public function query($sql, $parse = false)
	{
		if (!is_bool($parse) && !is_array($parse)) {
			$parse = func_get_args();
			array_shift($parse);
		}

		$sql = $this->parseSql($sql, $parse);
		return $this->db->query($sql);
	}

	public function execute($sql, $parse = false)
	{
		if (!is_bool($parse) && !is_array($parse)) {
			$parse = func_get_args();
			array_shift($parse);
		}

		$sql = $this->parseSql($sql, $parse);
		return $this->db->execute($sql);
	}

	protected function parseSql($sql, $parse)
	{
		if (true === $parse) {
			$options = $this->_parseOptions();
			$sql = $this->db->parseSql($sql, $options);
		}
		else if (is_array($parse)) {
			$sql = vsprintf($sql, $parse);
		}
		else {
			$sql = strtr($sql, array('__TABLE__' => $this->getTableName(), '__PREFIX__' => c('DB_PREFIX')));
		}

		$this->db->setModel($this->name);
		return $sql;
	}

	public function db($linkNum = '', $config = '', $params = array())
	{
		if (('' === $linkNum) && $this->db) {
			return $this->db;
		}

		static $_linkNum = array();
		static $_db = array();
		if (!isset($_db[$linkNum]) || (isset($_db[$linkNum]) && $config && ($_linkNum[$linkNum] != $config))) {
			if (!empty($config) && is_string($config) && (false === strpos($config, '/'))) {
				$config = c($config);
			}

			$_db[$linkNum] = Db::getInstance($config);
		}
		else if (NULL === $config) {
			$_db[$linkNum]->close();
			unset($_db[$linkNum]);
			return NULL;
		}

		if (!empty($params)) {
			if (is_string($params)) {
				parse_str($params, $params);
			}

			foreach ($params as $name => $value) {
				$this->setProperty($name, $value);
			}
		}

		$_linkNum[$linkNum] = $config;
		$this->db = $_db[$linkNum];
		$this->_after_db();
		if (!empty($this->name) && $this->autoCheckFields) {
			$this->_checkTableInfo();
		}

		return $this;
	}

	protected function _after_db()
	{
	}

	public function getModelName()
	{
		if (empty($this->name)) {
			$this->name = substr(get_class($this), 0, -5);
		}

		return $this->name;
	}

	public function getTableName()
	{
		if (empty($this->trueTableName)) {
			$tableName = (!empty($this->tablePrefix) ? $this->tablePrefix : '');

			if (!empty($this->tableName)) {
				$tableName .= $this->tableName;
			}
			else {
				$tableName .= parse_name($this->name);
			}

			$this->trueTableName = strtolower($tableName);
		}

		return (!empty($this->dbName) ? $this->dbName . '.' : '') . $this->trueTableName;
	}

	public function startTrans()
	{
		$this->commit();
		$this->db->startTrans();
		return NULL;
	}

	public function commit()
	{
		return $this->db->commit();
	}

	public function rollback()
	{
		return $this->db->rollback();
	}

	public function getError()
	{
		return $this->error;
	}

	public function getDbError()
	{
		return $this->db->getError();
	}

	public function getLastInsID()
	{
		return $this->db->getLastInsID();
	}

	public function getLastSql()
	{
		return $this->db->getLastSql($this->name);
	}

	public function _sql()
	{
		return $this->getLastSql();
	}

	public function getPk()
	{
		return isset($this->fields['_pk']) ? $this->fields['_pk'] : $this->pk;
	}

	public function getDbFields()
	{
		if (isset($this->options['table'])) {
			$fields = $this->db->getFields($this->options['table']);
			return $fields ? array_keys($fields) : false;
		}

		if ($this->fields) {
			$fields = $this->fields;
			unset($fields['_autoinc']);
			unset($fields['_pk']);
			unset($fields['_type']);
			unset($fields['_version']);
			return $fields;
		}

		return false;
	}

	public function data($data = '')
	{
		if (('' === $data) && !empty($this->data)) {
			return $this->data;
		}

		if (is_object($data)) {
			$data = get_object_vars($data);
		}
		else if (is_string($data)) {
			parse_str($data, $data);
		}
		else if (!is_array($data)) {
			throw_exception(l('_DATA_TYPE_INVALID_'));
		}

		$this->data = $data;
		return $this;
	}

	public function join($join)
	{
		if (is_array($join)) {
			$this->options['join'] = $join;
		}
		else if (!empty($join)) {
			$this->options['join'][] = $join;
		}

		return $this;
	}

	public function union($union, $all = false)
	{
		if (empty($union)) {
			return $this;
		}

		if ($all) {
			$this->options['union']['_all'] = true;
		}

		if (is_object($union)) {
			$union = get_object_vars($union);
		}

		if (is_string($union)) {
			$options = $union;
		}
		else if (is_array($union)) {
			if (isset($union[0])) {
				$this->options['union'] = array_merge($this->options['union'], $union);
				return $this;
			}
			else {
				$options = $union;
			}
		}
		else {
			throw_exception(l('_DATA_TYPE_INVALID_'));
		}

		$this->options['union'][] = $options;
		return $this;
	}

	public function cache($key = true, $expire = NULL, $type = '')
	{
		if (false !== $key) {
			$this->options['cache'] = array('key' => $key, 'expire' => $expire, 'type' => $type);
		}

		return $this;
	}

	public function field($field, $except = false)
	{
		if (true === $field) {
			$fields = $this->getDbFields();
			$field = ($fields ? $fields : '*');
		}
		else if ($except) {
			if (is_string($field)) {
				$field = explode(',', $field);
			}

			$fields = $this->getDbFields();
			$field = ($fields ? array_diff($fields, $field) : $field);
		}

		$this->options['field'] = $field;
		return $this;
	}

	public function scope($scope = '', $args = NULL)
	{
		if ('' === $scope) {
			if (isset($this->_scope['default'])) {
				$options = $this->_scope['default'];
			}
			else {
				return $this;
			}
		}
		else if (is_string($scope)) {
			$scopes = explode(',', $scope);
			$options = array();

			foreach ($scopes as $name) {
				if (!isset($this->_scope[$name])) {
					continue;
				}

				$options = array_merge($options, $this->_scope[$name]);
			}

			if (!empty($args) && is_array($args)) {
				$options = array_merge($options, $args);
			}
		}
		else if (is_array($scope)) {
			$options = $scope;
		}

		if (is_array($options) && !empty($options)) {
			$this->options = array_merge($this->options, array_change_key_case($options));
		}

		return $this;
	}

	public function where($where, $parse = NULL)
	{
		if (!is_null($parse) && is_string($where)) {
			if (!is_array($parse)) {
				$parse = func_get_args();
				array_shift($parse);
			}

			$parse = array_map(array($this->db, 'escapeString'), $parse);
			$where = vsprintf($where, $parse);
		}
		else if (is_object($where)) {
			$where = get_object_vars($where);
		}

		if (is_string($where) && ('' != $where)) {
			$map = array();
			$map['_string'] = $where;
			$where = $map;
		}

		if (isset($this->options['where'])) {
			$this->options['where'] = array_merge($this->options['where'], $where);
		}
		else {
			$this->options['where'] = $where;
		}

		return $this;
	}

	public function limit($offset, $length = NULL)
	{
		$this->options['limit'] = is_null($length) ? $offset : $offset . ',' . $length;
		return $this;
	}

	public function page($page, $listRows = NULL)
	{
		$this->options['page'] = is_null($listRows) ? $page : $page . ',' . $listRows;
		return $this;
	}

	public function comment($comment)
	{
		$this->options['comment'] = $comment;
		return $this;
	}

	public function setProperty($name, $value)
	{
		if (property_exists($this, $name)) {
			$this->$name = $value;
		}

		return $this;
	}
}

class Db
{
	protected $dbType;
	protected $autoFree = false;
	protected $model = '_think_';
	protected $pconnect = false;
	protected $queryStr = '';
	protected $modelSql = array();
	protected $lastInsID;
	protected $numRows = 0;
	protected $numCols = 0;
	protected $transTimes = 0;
	protected $error = '';
	protected $linkID = array();
	protected $_linkID;
	protected $queryID;
	protected $connected = false;
	protected $config = '';
	protected $comparison = array('eq' => '=', 'neq' => '<>', 'gt' => '>', 'egt' => '>=', 'lt' => '<', 'elt' => '<=', 'notlike' => 'NOT LIKE', 'like' => 'LIKE', 'in' => 'IN', 'notin' => 'NOT IN');
	protected $selectSql = 'SELECT%DISTINCT% %FIELD% FROM %TABLE%%JOIN%%WHERE%%GROUP%%HAVING%%ORDER%%LIMIT% %UNION%%COMMENT%';

	static public function getInstance()
	{
		$args = func_get_args();
		return get_instance_of('Db', 'factory', $args);
	}

	public function factory($db_config = '')
	{
		$db_config = $this->parseConfig($db_config);

		if (empty($db_config['dbms'])) {
			throw_exception(l('_NO_DB_CONFIG_'));
		}

		$this->dbType = ucwords(strtolower($db_config['dbms']));
		$class = 'Db' . $this->dbType;

		if (class_exists($class)) {
			$db = new $class($db_config);

			if ('pdo' != strtolower($db_config['dbms'])) {
				$db->dbType = strtoupper($this->dbType);
			}
			else {
				$db->dbType = $this->_getDsnType($db_config['dsn']);
			}
		}
		else {
			throw_exception(l('_NO_DB_DRIVER_') . ': ' . $class);
		}

		return $db;
	}

	protected function _getDsnType($dsn)
	{
		$match = explode(':', $dsn);
		$dbType = strtoupper(trim($match[0]));
		return $dbType;
	}

	private function parseConfig($db_config = '')
	{
		if (!empty($db_config) && is_string($db_config)) {
			$db_config = $this->parseDSN($db_config);
		}
		else if (is_array($db_config)) {
			$db_config = array_change_key_case($db_config);
			$db_config = array('dbms' => $db_config['db_type'], 'username' => $db_config['db_user'], 'password' => $db_config['db_pwd'], 'hostname' => $db_config['db_host'], 'hostport' => $db_config['db_port'], 'database' => $db_config['db_name'], 'dsn' => $db_config['db_dsn'], 'params' => $db_config['db_params']);
		}
		else if (empty($db_config)) {
			if (c('DB_DSN') && ('pdo' != strtolower(c('DB_TYPE')))) {
				$db_config = $this->parseDSN(c('DB_DSN'));
			}
			else {
				$db_config = array('dbms' => c('DB_TYPE'), 'username' => c('DB_USER'), 'password' => c('DB_PWD'), 'hostname' => c('DB_HOST'), 'hostport' => c('DB_PORT'), 'database' => c('DB_NAME'), 'dsn' => c('DB_DSN'), 'params' => c('DB_PARAMS'));
			}
		}

		return $db_config;
	}

	protected function initConnect($master = true)
	{
		if (1 == c('DB_DEPLOY_TYPE')) {
			$this->_linkID = $this->multiConnect($master);
		}
		else if (!$this->connected) {
			$this->_linkID = $this->connect();
		}
	}

	protected function multiConnect($master = false)
	{
		static $_config = array();

		if (empty($_config)) {
			foreach ($this->config as $key => $val) {
				$_config[$key] = explode(',', $val);
			}
		}

		if (c('DB_RW_SEPARATE')) {
			if ($master) {
				$r = floor(mt_rand(0, c('DB_MASTER_NUM') - 1));
			}
			else if (is_numeric(c('DB_SLAVE_NO'))) {
				$r = c('DB_SLAVE_NO');
			}
			else {
				$r = floor(mt_rand(c('DB_MASTER_NUM'), count($_config['hostname']) - 1));
			}
		}
		else {
			$r = floor(mt_rand(0, count($_config['hostname']) - 1));
		}

		$db_config = array('username' => isset($_config['username'][$r]) ? $_config['username'][$r] : $_config['username'][0], 'password' => isset($_config['password'][$r]) ? $_config['password'][$r] : $_config['password'][0], 'hostname' => isset($_config['hostname'][$r]) ? $_config['hostname'][$r] : $_config['hostname'][0], 'hostport' => isset($_config['hostport'][$r]) ? $_config['hostport'][$r] : $_config['hostport'][0], 'database' => isset($_config['database'][$r]) ? $_config['database'][$r] : $_config['database'][0], 'dsn' => isset($_config['dsn'][$r]) ? $_config['dsn'][$r] : $_config['dsn'][0], 'params' => isset($_config['params'][$r]) ? $_config['params'][$r] : $_config['params'][0]);
		return $this->connect($db_config, $r);
	}

	public function parseDSN($dsnStr)
	{
		if (empty($dsnStr)) {
			return false;
		}

		$info = parse_url($dsnStr);

		if ($info['scheme']) {
			$dsn = array('dbms' => $info['scheme'], 'username' => isset($info['user']) ? $info['user'] : '', 'password' => isset($info['pass']) ? $info['pass'] : '', 'hostname' => isset($info['host']) ? $info['host'] : '', 'hostport' => isset($info['port']) ? $info['port'] : '', 'database' => isset($info['path']) ? substr($info['path'], 1) : '');
		}
		else {
			preg_match('/^(.*?)\\:\\/\\/(.*?)\\:(.*?)\\@(.*?)\\:([0-9]{1, 6})\\/(.*?)$/', trim($dsnStr), $matches);
			$dsn = array('dbms' => $matches[1], 'username' => $matches[2], 'password' => $matches[3], 'hostname' => $matches[4], 'hostport' => $matches[5], 'database' => $matches[6]);
		}

		$dsn['dsn'] = '';
		return $dsn;
	}

	protected function debug()
	{
		$this->modelSql[$this->model] = $this->queryStr;
		$this->model = '_think_';

		if (c('DB_SQL_LOG')) {
			g('queryEndTime');
			trace($this->queryStr . ' [ RunTime:' . g('queryStartTime', 'queryEndTime', 6) . 's ]', '', 'SQL');
		}
	}

	protected function parseLock($lock = false)
	{
		if (!$lock) {
			return '';
		}

		if ('ORACLE' == $this->dbType) {
			return ' FOR UPDATE NOWAIT ';
		}

		return ' FOR UPDATE ';
	}

	protected function parseSet($data)
	{
		foreach ($data as $key => $val) {
			$value = $this->parseValue($val);

			if (is_scalar($value)) {
				$set[] = $this->parseKey($key) . '=' . $value;
			}
		}

		return ' SET ' . implode(',', $set);
	}

	protected function parseKey(&$key)
	{
		return $key;
	}

	protected function parseValue($value)
	{
		if (is_string($value)) {
			$value = '\'' . $this->escapeString($value) . '\'';
		}
		else {
			if (isset($value[0]) && is_string($value[0]) && (strtolower($value[0]) == 'exp')) {
				$value = $this->escapeString($value[1]);
			}
			else if (is_array($value)) {
				$value = array_map(array($this, 'parseValue'), $value);
			}
			else if (is_bool($value)) {
				$value = ($value ? '1' : '0');
			}
			else if (is_null($value)) {
				$value = 'null';
			}
		}

		return $value;
	}

	protected function parseField($fields)
	{
		if (is_string($fields) && strpos($fields, ',')) {
			$fields = explode(',', $fields);
		}

		if (is_array($fields)) {
			$array = array();

			foreach ($fields as $key => $field) {
				if (!is_numeric($key)) {
					$array[] = $this->parseKey($key) . ' AS ' . $this->parseKey($field);
				}
				else {
					$array[] = $this->parseKey($field);
				}
			}

			$fieldsStr = implode(',', $array);
		}
		else {
			if (is_string($fields) && !empty($fields)) {
				$fieldsStr = $this->parseKey($fields);
			}
			else {
				$fieldsStr = '*';
			}
		}

		return $fieldsStr;
	}

	protected function parseTable($tables)
	{
		if (is_array($tables)) {
			$array = array();

			foreach ($tables as $table => $alias) {
				if (!is_numeric($table)) {
					$array[] = $this->parseKey($table) . ' ' . $this->parseKey($alias);
				}
				else {
					$array[] = $this->parseKey($table);
				}
			}

			$tables = $array;
		}
		else if (is_string($tables)) {
			$tables = explode(',', $tables);
			array_walk($tables, array(&$this, 'parseKey'));
		}

		return implode(',', $tables);
	}

	protected function parseWhere($where)
	{
		$whereStr = '';

		if (is_string($where)) {
			$whereStr = $where;
		}
		else {
			$operate = (isset($where['_logic']) ? strtoupper($where['_logic']) : '');

			if (in_array($operate, array('AND', 'OR', 'XOR'))) {
				$operate = ' ' . $operate . ' ';
				unset($where['_logic']);
			}
			else {
				$operate = ' AND ';
			}

			foreach ($where as $key => $val) {
				$whereStr .= '( ';

				if (0 === strpos($key, '_')) {
					$whereStr .= $this->parseThinkWhere($key, $val);
				}
				else {
					if (!preg_match('/^[A-Z_\\|\\&\\-.a-z0-9\\(\\)\\,]+$/', trim($key))) {
						throw_exception(l('_EXPRESS_ERROR_') . ':' . $key);
					}

					$multi = is_array($val) && isset($val['_multi']);
					$key = trim($key);

					if (strpos($key, '|')) {
						$array = explode('|', $key);
						$str = array();

						foreach ($array as $m => $k) {
							$v = ($multi ? $val[$m] : $val);
							$str[] = '(' . $this->parseWhereItem($this->parseKey($k), $v) . ')';
						}

						$whereStr .= implode(' OR ', $str);
					}
					else if (strpos($key, '&')) {
						$array = explode('&', $key);
						$str = array();

						foreach ($array as $m => $k) {
							$v = ($multi ? $val[$m] : $val);
							$str[] = '(' . $this->parseWhereItem($this->parseKey($k), $v) . ')';
						}

						$whereStr .= implode(' AND ', $str);
					}
					else {
						$whereStr .= $this->parseWhereItem($this->parseKey($key), $val);
					}
				}

				$whereStr .= ' )' . $operate;
			}

			$whereStr = substr($whereStr, 0, 0 - strlen($operate));
		}

		return empty($whereStr) ? '' : ' WHERE ' . $whereStr;
	}

	protected function parseWhereItem($key, $val)
	{
		$whereStr = '';

		if (is_array($val)) {
			if (is_string($val[0])) {
				if (preg_match('/^(EQ|NEQ|GT|EGT|LT|ELT)$/i', $val[0])) {
					$whereStr .= $key . ' ' . $this->comparison[strtolower($val[0])] . ' ' . $this->parseValue($val[1]);
				}
				else if (preg_match('/^(NOTLIKE|LIKE)$/i', $val[0])) {
					if (is_array($val[1])) {
						$likeLogic = (isset($val[2]) ? strtoupper($val[2]) : 'OR');

						if (in_array($likeLogic, array('AND', 'OR', 'XOR'))) {
							$likeStr = $this->comparison[strtolower($val[0])];
							$like = array();

							foreach ($val[1] as $item) {
								$like[] = $key . ' ' . $likeStr . ' ' . $this->parseValue($item);
							}

							$whereStr .= '(' . implode(' ' . $likeLogic . ' ', $like) . ')';
						}
					}
					else {
						$whereStr .= $key . ' ' . $this->comparison[strtolower($val[0])] . ' ' . $this->parseValue($val[1]);
					}
				}
				else if ('exp' == strtolower($val[0])) {
					$whereStr .= ' (' . $key . ' ' . $val[1] . ') ';
				}
				else if (preg_match('/IN/i', $val[0])) {
					if (isset($val[2]) && ('exp' == $val[2])) {
						$whereStr .= $key . ' ' . strtoupper($val[0]) . ' ' . $val[1];
					}
					else {
						if (is_string($val[1])) {
							$val[1] = explode(',', $val[1]);
						}

						$zone = implode(',', $this->parseValue($val[1]));
						$whereStr .= $key . ' ' . strtoupper($val[0]) . ' (' . $zone . ')';
					}
				}
				else if (preg_match('/BETWEEN/i', $val[0])) {
					$data = (is_string($val[1]) ? explode(',', $val[1]) : $val[1]);
					$whereStr .= ' (' . $key . ' ' . strtoupper($val[0]) . ' ' . $this->parseValue($data[0]) . ' AND ' . $this->parseValue($data[1]) . ' )';
				}
				else {
					throw_exception(l('_EXPRESS_ERROR_') . ':' . $val[0]);
				}
			}
			else {
				$count = count($val);
				$rule = (isset($val[$count - 1]) ? strtoupper($val[$count - 1]) : '');

				if (in_array($rule, array('AND', 'OR', 'XOR'))) {
					$count = $count - 1;
				}
				else {
					$rule = 'AND';
				}

				for ($i = 0; $i < $count; $i++) {
					$data = (is_array($val[$i]) ? $val[$i][1] : $val[$i]);

					if ('exp' == strtolower($val[$i][0])) {
						$whereStr .= '(' . $key . ' ' . $data . ') ' . $rule . ' ';
					}
					else {
						$op = (is_array($val[$i]) ? $this->comparison[strtolower($val[$i][0])] : '=');
						$whereStr .= '(' . $key . ' ' . $op . ' ' . $this->parseValue($data) . ') ' . $rule . ' ';
					}
				}

				$whereStr = substr($whereStr, 0, -4);
			}
		}
		else {
			if (c('DB_LIKE_FIELDS') && preg_match('/(' . c('DB_LIKE_FIELDS') . ')/i', $key)) {
				$val = '%' . $val . '%';
				$whereStr .= $key . ' LIKE ' . $this->parseValue($val);
			}
			else {
				$whereStr .= $key . ' = ' . $this->parseValue($val);
			}
		}

		return $whereStr;
	}

	protected function parseThinkWhere($key, $val)
	{
		$whereStr = '';

		switch ($key) {
		case '_string':
			$whereStr = $val;
			break;

		case '_complex':
			$whereStr = substr($this->parseWhere($val), 6);
			break;

		case '_query':
			parse_str($val, $where);

			if (isset($where['_logic'])) {
				$op = ' ' . strtoupper($where['_logic']) . ' ';
				unset($where['_logic']);
			}
			else {
				$op = ' AND ';
			}

			$array = array();

			foreach ($where as $field => $data) {
				$array[] = $this->parseKey($field) . ' = ' . $this->parseValue($data);
			}

			$whereStr = implode($op, $array);
			break;
		}

		return $whereStr;
	}

	protected function parseLimit($limit)
	{
		return !empty($limit) ? ' LIMIT ' . $limit . ' ' : '';
	}

	protected function parseJoin($join)
	{
		$joinStr = '';

		if (!empty($join)) {
			if (is_array($join)) {
				foreach ($join as $key => $_join) {
					if (false !== stripos($_join, 'JOIN')) {
						$joinStr .= ' ' . $_join;
					}
					else {
						$joinStr .= ' LEFT JOIN ' . $_join;
					}
				}
			}
			else {
				$joinStr .= ' LEFT JOIN ' . $join;
			}
		}

		$joinStr = preg_replace('/__([A-Z_-]+)__/esU', c('DB_PREFIX') . '.strtolower(\'$1\')', $joinStr);
		return $joinStr;
	}

	protected function parseOrder($order)
	{
		if (is_array($order)) {
			$array = array();

			foreach ($order as $key => $val) {
				if (is_numeric($key)) {
					$array[] = $this->parseKey($val);
				}
				else {
					$array[] = $this->parseKey($key) . ' ' . $val;
				}
			}

			$order = implode(',', $array);
		}

		return !empty($order) ? ' ORDER BY ' . $order : '';
	}

	protected function parseGroup($group)
	{
		return !empty($group) ? ' GROUP BY ' . $group : '';
	}

	protected function parseHaving($having)
	{
		return !empty($having) ? ' HAVING ' . $having : '';
	}

	protected function parseComment($comment)
	{
		return !empty($comment) ? ' /* ' . $comment . ' */' : '';
	}

	protected function parseDistinct($distinct)
	{
		return !empty($distinct) ? ' DISTINCT ' : '';
	}

	protected function parseUnion($union)
	{
		if (empty($union)) {
			return '';
		}

		if (isset($union['_all'])) {
			$str = 'UNION ALL ';
			unset($union['_all']);
		}
		else {
			$str = 'UNION ';
		}

		foreach ($union as $u) {
			$sql[] = $str . (is_array($u) ? $this->buildSelectSql($u) : $u);
		}

		return implode(' ', $sql);
	}

	public function insert($data, $options = array(), $replace = false)
	{
		$values = $fields = array();
		$this->model = $options['model'];

		foreach ($data as $key => $val) {
			$value = $this->parseValue($val);

			if (is_scalar($value)) {
				$values[] = $value;
				$fields[] = $this->parseKey($key);
			}
		}

		$sql = ($replace ? 'REPLACE' : 'INSERT') . ' INTO ' . $this->parseTable($options['table']) . ' (' . implode(',', $fields) . ') VALUES (' . implode(',', $values) . ')';
		$sql .= $this->parseLock(isset($options['lock']) ? $options['lock'] : false);
		$sql .= $this->parseComment(!empty($options['comment']) ? $options['comment'] : '');
		return $this->execute($sql);
	}

	public function selectInsert($fields, $table, $options = array())
	{
		$this->model = $options['model'];

		if (is_string($fields)) {
			$fields = explode(',', $fields);
		}

		array_walk($fields, array($this, 'parseKey'));
		$sql = 'INSERT INTO ' . $this->parseTable($table) . ' (' . implode(',', $fields) . ') ';
		$sql .= $this->buildSelectSql($options);
		return $this->execute($sql);
	}

	public function update($data, $options)
	{
		$this->model = $options['model'];
		$sql = 'UPDATE ' . $this->parseTable($options['table']) . $this->parseSet($data) . $this->parseWhere(!empty($options['where']) ? $options['where'] : '') . $this->parseOrder(!empty($options['order']) ? $options['order'] : '') . $this->parseLimit(!empty($options['limit']) ? $options['limit'] : '') . $this->parseLock(isset($options['lock']) ? $options['lock'] : false) . $this->parseComment(!empty($options['comment']) ? $options['comment'] : '');
		return $this->execute($sql);
	}

	public function delete($options = array())
	{
		$this->model = $options['model'];
		$sql = 'DELETE FROM ' . $this->parseTable($options['table']) . $this->parseWhere(!empty($options['where']) ? $options['where'] : '') . $this->parseOrder(!empty($options['order']) ? $options['order'] : '') . $this->parseLimit(!empty($options['limit']) ? $options['limit'] : '') . $this->parseLock(isset($options['lock']) ? $options['lock'] : false) . $this->parseComment(!empty($options['comment']) ? $options['comment'] : '');
		return $this->execute($sql);
	}

	public function select($options = array())
	{
		$this->model = $options['model'];
		$M = c('M');

		if ($M[$options['model']]) {
			$options['table'] = array(C('DB_PREFIX').'content' => 'a', $options['table'] => 'b');
		}

		$sql = $this->buildSelectSql($options);
		$cache = (isset($options['cache']) ? $options['cache'] : false);

		if ($cache) {
			$key = (is_string($cache['key']) ? $cache['key'] : md5($sql));
			$value = s($key, '', $cache);

			if (false !== $value) {
				return $value;
			}
		}

		$result = $this->query($sql);
		if ($cache && (false !== $result)) {
			s($key, $result, $cache);
		}

		return $result;
	}

	public function buildSelectSql($options = array())
	{
		if (isset($options['page'])) {
			if (strpos($options['page'], ',')) {
				list($page, $listRows) = explode(',', $options['page']);
			}
			else {
				$page = $options['page'];
			}

			$page = ($page ? $page : 1);
			$listRows = (isset($listRows) ? $listRows : (is_numeric($options['limit']) ? $options['limit'] : 20));
			$offset = $listRows * ((int) $page - 1);
			$options['limit'] = $offset . ',' . $listRows;
		}

		if (c('DB_SQL_BUILD_CACHE')) {
			$key = md5(serialize($options));
			$value = s($key);

			if (false !== $value) {
				return $value;
			}
		}

		$sql = $this->parseSql($this->selectSql, $options);
		$sql .= $this->parseLock(isset($options['lock']) ? $options['lock'] : false);

		if (isset($key)) {
			s($key, $sql, array('expire' => 0, 'length' => c('DB_SQL_BUILD_LENGTH'), 'queue' => c('DB_SQL_BUILD_QUEUE')));
		}

		return $sql;
	}

	public function parseSql($sql, $options = array())
	{
		$sql = str_replace(array('%TABLE%', '%DISTINCT%', '%FIELD%', '%JOIN%', '%WHERE%', '%GROUP%', '%HAVING%', '%ORDER%', '%LIMIT%', '%UNION%', '%COMMENT%'), array($this->parseTable($options['table']), $this->parseDistinct(isset($options['distinct']) ? $options['distinct'] : false), $this->parseField(!empty($options['field']) ? $options['field'] : '*'), $this->parseJoin(!empty($options['join']) ? $options['join'] : ''), $this->parseWhere(!empty($options['where']) ? $options['where'] : ''), $this->parseGroup(!empty($options['group']) ? $options['group'] : ''), $this->parseHaving(!empty($options['having']) ? $options['having'] : ''), $this->parseOrder(!empty($options['order']) ? $options['order'] : ''), $this->parseLimit(!empty($options['limit']) ? $options['limit'] : ''), $this->parseUnion(!empty($options['union']) ? $options['union'] : ''), $this->parseComment(!empty($options['comment']) ? $options['comment'] : '')), $sql);
		return $sql;
	}

	public function getLastSql($model = '')
	{
		return $model ? $this->modelSql[$model] : $this->queryStr;
	}

	public function getLastInsID()
	{
		return $this->lastInsID;
	}

	public function getError()
	{
		return $this->error;
	}

	public function escapeString($str)
	{
		return addslashes($str);
	}

	public function setModel($model)
	{
		$this->model = $model;
	}

	public function __destruct()
	{
		if ($this->queryID) {
			$this->free();
		}

		$this->close();
	}

	public function close()
	{
	}
}

class Cache
{
	protected $handler;
	protected $options = array();

	public function connect($type = '', $options = array())
	{
		if (empty($type)) {
			$type = c('DATA_CACHE_TYPE');
		}

		$type = strtolower(trim($type));
		$class = 'Cache' . ucwords($type);

		if (class_exists($class)) {
			$cache = new $class($options);
		}
		else {
			throw_exception(l('_CACHE_TYPE_INVALID_') . ':' . $type);
		}

		return $cache;
	}

	public function __get($name)
	{
		return $this->get($name);
	}

	public function __set($name, $value)
	{
		return $this->set($name, $value);
	}

	public function __unset($name)
	{
		$this->rm($name);
	}

	public function setOptions($name, $value)
	{
		$this->options[$name] = $value;
	}

	public function getOptions($name)
	{
		return $this->options[$name];
	}

	static public function getInstance()
	{
		$param = func_get_args();
		return get_instance_of('Cache', 'connect', $param);
	}

	protected function queue($key)
	{
		static $_handler = array(
			'file'   => array('F', 'F'),
			'xcache' => array('xcache_get', 'xcache_set'),
			'apc'    => array('apc_fetch', 'apc_store')
			);
		$queue = (isset($this->options['queue']) ? $this->options['queue'] : 'file');
		$fun = (isset($_handler[$queue]) ? $_handler[$queue] : $_handler['file']);
		$queue_name = (isset($this->options['queue_name']) ? $this->options['queue_name'] : 'think_queue');
		$value = $fun[0]($queue_name);

		if (!$value) {
			$value = array();
		}

		if (false === array_search($key, $value)) {
			array_push($value, $key);
		}

		if ($this->options['length'] < count($value)) {
			$key = array_shift($value);
			$this->rm($key);

			if (APP_DEUBG) {
				n($queue_name . '_out_times', 1, true);
			}
		}

		return $fun[1]($queue_name, $value);
	}

	public function __call($method, $args)
	{
		if (method_exists($this->handler, $method)) {
			return call_user_func_array(array($this->handler, $method), $args);
		}
		else {
			throw_exception('Cache' . ':' . $method . l('_METHOD_NOT_EXIST_'));
			return NULL;
		}
	}
}

$GLOBALS['_beginTime'] = microtime(true);
define('MEMORY_LIMIT_ON', function_exists('memory_get_usage'));

if (MEMORY_LIMIT_ON) {
	$GLOBALS['_startUseMems'] = memory_get_usage();
}

if (!defined('UPLOAD_PATH')) {
	define('UPLOAD_PATH', YOURPHP_PATH . 'Uploads/');
}

define('YOURPHP_CORE', YOURPHP_PATH . 'Core/');
define('CACHE_PATH', YOURPHP_PATH . 'Cache/');
define('APP_LANG', 1);
define('Yourphp', 1);

if ($_GET['g'] == 'Admin') {
	$var = include YOURPHP_PATH . 'version.php';
	define('VERSION', $var['VERSION']);
	define('UPDATETIME', $var['UPDATETIME']);

	if (strpos($_SERVER['SCRIPT_NAME'], 'index.php')) {
		exit();
	}
}

if ($_GET['m'] == 'Attachment') {
	$_GET['g'] = 'Admin';
}

include YOURPHP_CORE . 'Fun/common.php';

if (defined('YP_KEY')) {
	exit();
}

@preg_match('/[\\w][\\w-]*\\.(?:com\\.cn|net\\.cn|org\\.cn|gov\\.cn|com|cn|co|net|org|gov|cc|biz|info)(\\/|$)/isU', $_SERVER['SERVER_NAME'], $domain);
$YPliuxun_domain = $domain[0];

if (@is_file(YOURPHP_PATH . $YPliuxun_domain . '.php')) {
	@include YOURPHP_PATH . $YPliuxun_domain . '.php';

	if (!$is_yourphp) {
		exit();
	}

	$YP_code = authcode($YP_code, $operation = 'DECODE', $YP_key . '_' . $YPliuxun_domain);

	if (sha1($YPliuxun_domain . $YP_key) == $YP_code) {
		@define('YP_KEY', $YP_key);
	}
	else {
		@define('YP_KEY', false);
	}

	unset($is_yourphp);
	unset($YP_key);
	unset($YP_code);
}
else {
	define('YP_KEY', false);
}

unset($YPliuxun_domain);
unset($domain);
g('loadTime');
Yourphp::Start();

?>
