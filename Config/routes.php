<?php
Router::connect('/auth', array('controller' => 'Auth', 'action' => 'version', 'plugin' => 'Auth'));
Router::connect('/auth/authenticate', array('controller' => 'Auth', 'action' => 'authenticate', 'plugin' => 'Auth'));
Router::connect('/auth/refresh', array('controller' => 'Auth', 'action' => 'refresh', 'plugin' => 'Auth'));
Router::connect('/auth/invalidate', array('controller' => 'Auth', 'action' => 'invalidate', 'plugin' => 'Auth'));
Router::connect('/auth/v', array('controller' => 'Auth', 'action' => 'version', 'plugin' => 'Auth'));
Router::connect('/auth/version', array('controller' => 'Auth', 'action' => 'version', 'plugin' => 'Auth'));
Router::connect('/auth/getprivatekey', array('controller' => 'Auth', 'action' => 'getPrivateKey', 'plugin' => 'Auth'));