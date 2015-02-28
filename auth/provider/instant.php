<?php

namespace arseniyk\instant\auth\provider;

class instant extends \phpbb\auth\provider\base

{

    public function __construct(\phpbb\db\driver\driver_interface $db)
    {
        $this->db = $db;
    }

    public function login($username, $password)
    {
        // Auth plugins get the password untrimmed.
        // For compatibility we trim() here.
        $password = trim($password);

        // do not allow empty password
        if (!$password)
        {
            return array(
                'status'    => LOGIN_ERROR_PASSWORD,
                'error_msg'    => 'NO_PASSWORD_SUPPLIED',
                'user_row'    => array('user_id' => ANONYMOUS),
            );
        }

        if (!$username)
        {
            return array(
                'status'    => LOGIN_ERROR_USERNAME,
                'error_msg'    => 'LOGIN_ERROR_USERNAME',
                'user_row'    => array('user_id' => ANONYMOUS),
            );
        }

        $username_clean = utf8_clean_string($username);
		$logged_id  = cmsUser::login($email, $password, $remember);
		
		 $sql = 'SELECT user_id, username, user_password, user_passchg, user_pass_convert, user_email, user_type, user_login_attempts
            FROM ' . USERS_TABLE . "
            WHERE username_clean = '" . $this->db->sql_escape($username_clean) . "'";
        $result = $this->db->sql_query($sql);
        $row = $this->db->sql_fetchrow($result);
        $this->db->sql_freeresult($result);
		
		if ( $logged_id ){
			// Successful login... set user_login_attempts to zero...
			if ($row) {
				return array(
					'status'        => LOGIN_SUCCESS,
					'error_msg'        => false,
					'user_row'        => $row,
				);
			}
			return array(
					'status'        => LOGIN_SUCCESS_CREATE_PROFILE,
					'error_msg'        => false,
					'user_row'     => array(
                           "username"       => \cmsUser::get('nickname'),  // Отображаемое имя пользователя
                           "user_password"  => '',  // phpbb-хеш пароля
                           "user_email"     => $username_clean,  // E-mail пользователя, если существует
                           "user_type"      => 0,
                           "group_id" => 2
                       ),
				);
			
		}
    }
}
?>