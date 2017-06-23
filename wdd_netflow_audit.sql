
use lzhang;
drop table if exists `wdd_netflow_audit`;
create table `wdd_netflow_audit`
(
`id` bigint(20) unsigned not null auto_increment,
`auditid` bigint(20) unsigned default null,
`starttime` datetime default NULL, 
`endtime` datetime default NULL, 
`ftype` int(10) unsigned default null,
`ftypename` varchar(10) default null,
`dmac` bigint(20) default null,
`smac` bigint(20) default null,
`sip` varchar(46) default null,
`dip` varchar(46) default null,
`sport` bigint unsigned default null,
`dport` bigint unsigned default null,
`reqpkts` bigint unsigned default null,
`rsppkts` bigint unsigned default null,
`reqflow` bigint unsigned default null,
`rspflow` bigint unsigned default null,
`sessionstate` int(2) default null,
`auditext1` varchar(255) default null,
`auditext2` varchar(255) default null,
key `id` (id)
)engine=MyISAM default charset=utf8;
