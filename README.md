# netflow_audit

CREATE TABLE `wdd_netflow_audit` (
`id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
`auditid` bigint(20) unsigned DEFAULT NULL,
`starttime` datetime DEFAULT NULL,
`endtime` datetime DEFAULT NULL,
`ftype` varchar(10) DEFAULT NULL,
`dmac` varchar(20) DEFAULT NULL,
`smac` varchar(20) DEFAULT NULL,
`sip` varchar(46) DEFAULT NULL,
`dip` varchar(46) DEFAULT NULL,
`sport` smallint(5) DEFAULT NULL,
`dport` smallint(5) DEFAULT NULL,
`reqflow` bigint(20) unsigned DEFAULT NULL,
`rspflow` bigint(20) unsigned DEFAULT NULL,
`sessionstate` int(2) DEFAULT NULL,
`auditext1` varchar(255) DEFAULT NULL,
`auditext2` varchar(255) DEFAULT NULL,
KEY `id` (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 
