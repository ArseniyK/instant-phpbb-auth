<?php

namespace arseniyk\instant\auth\provider;

class instant extends \phpbb\auth\provider\base {

    public function __construct(\phpbb\db\driver\driver_interface $db, \phpbb\passwords\manager $passwords_manager) {
        $this->db = $db;
		$this->passwords_manager = $passwords_manager;
    }

    public function login($username, $password) {
		error_log(print_r('login', TRUE)); 
        $password = trim($password);
        if (!$password) {
            return array(
                'status'    => LOGIN_ERROR_PASSWORD,
                'error_msg'    => 'NO_PASSWORD_SUPPLIED',
                'user_row'    => array('user_id' => ANONYMOUS),
            );
        }

        if (!$username) {
            return array(
                'status'    => LOGIN_ERROR_USERNAME,
                'error_msg'    => 'LOGIN_ERROR_USERNAME',
                'user_row'    => array('user_id' => ANONYMOUS),
            );
        }       		
		
		$sql = sprintf('SELECT nickname, email, password, password_salt FROM cms_users WHERE nickname = \'%1$s\'', $this->db->sql_escape($username));
		$iresult = $this->db->sql_query($sql);
		$irow = $this->db->sql_fetchrow($iresult);
		$this->db->sql_freeresult($iresult);
		if ($irow) {
		
			if ($irow["password"] == MD5(MD5($password) . $irow["password_salt"])) {
				$sql = sprintf('SELECT user_id, username, user_password, user_passchg, user_email, user_type FROM %1$s WHERE username = \'%2$s\'', USERS_TABLE, $this->db->sql_escape($username));
				$result = $this->db->sql_query($sql);
				$row = $this->db->sql_fetchrow($result);
				$this->db->sql_freeresult($result);
				if ($row){
					$hash = $this->passwords_manager->hash($password);
					if ($hash != $row["user_password"]) {
						$sql = 'UPDATE ' . USERS_TABLE . "
							SET user_password = '" . $this->db->sql_escape($hash) . "'
							WHERE user_id = {$row['user_id']}";
						$this->db->sql_query($sql);
					}
				   return array(
						'status'		=> LOGIN_SUCCESS,
						'error_msg'		=> false,
						'user_row'		=> $row,
					);
				}
				
				return array(
					'status'		=> LOGIN_SUCCESS_CREATE_PROFILE,
					'error_msg'		=> false,
					'user_row'		=> $this->newUserRow($irow["nickname"], $irow["email"], $irow["password"]),
				);
			
			}
			
			return array(
                'status'    => LOGIN_ERROR_PASSWORD,
                'error_msg'    => 'LOGIN_ERROR_PASSWORD',
                'user_row'    => array('user_id' => ANONYMOUS),
            );
		}
    }
	
	public function autologin()
	{	
		global $request;
		$auth_token = $request->variable(array("icms", "auth"), '', false, \phpbb\request\request_interface::COOKIE);
		$sql = sprintf('SELECT nickname, email, password FROM cms_users WHERE auth_token = \'%1$s\'', $this->db->sql_escape($auth_token));
		$iresult = $this->db->sql_query($sql);
		$irow = $this->db->sql_fetchrow($iresult);
		$this->db->sql_freeresult($iresult);
		if ($irow) {
			$sql = sprintf('SELECT user_id, username, user_password, user_passchg, user_email, user_type FROM %1$s WHERE username = \'%2$s\'', USERS_TABLE, $this->db->sql_escape($irow["nickname"]));
			$result = $this->db->sql_query($sql);
			$row = $this->db->sql_fetchrow($result);
			$this->db->sql_freeresult($result);
			if ($row) {
				$hash = $this->passwords_manager->hash($password);
				if ($hash != $row["user_password"]) {
					$sql = 'UPDATE ' . USERS_TABLE . "
						SET user_password = '" . $this->db->sql_escape($hash) . "'
						WHERE user_id = {$row['user_id']}";
					$this->db->sql_query($sql);
				}
				return $row;
			}
			
			if(!function_exists('user_add'))
			{
				include($this->phpbb_root_path . 'includes/functions_user.' . $this->php_ext);
			}

			user_add($this->newUserRow($irow["nickname"], $irow["email"], $irow["password"]));
			$result = $this->db->sql_query($sql);
			$row = $this->db->sql_fetchrow($result);
			$this->db->sql_freeresult($result);
			if ($row) {
				return $row;
			}			
		}
		return array();
	}
	
	private function newUserRow($username, $email, $password)
	{
		// first retrieve default group id
		$sql = sprintf('SELECT group_id FROM %1$s WHERE group_name = \'%2$s\' AND group_type = \'%3$s\'', GROUPS_TABLE, $this->db->sql_escape('REGISTERED'), GROUP_SPECIAL);
		$result = $this->db->sql_query($sql);
		$row = $this->db->sql_fetchrow($result);
		$this->db->sql_freeresult($result);

		if(!$row)
		{
			trigger_error('NO_GROUP');
		}

		// generate user account data
		return array(
			'username'		=> $username,
			'user_password'	=> $this->passwords_manager->hash($password),
			'user_email'	=> $email,
			'group_id'		=> (int)$row['group_id'],
			'user_type'		=> USER_NORMAL,			
		);
	}
}
?>
