-- MySQL dump 10.13  Distrib 5.1.51, for pc-linux-gnu (x86_64)
--
-- Host: localhost    Database: cvechecker
-- ------------------------------------------------------
-- Server version	5.1.51-log

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `tb_binmatch`
--

DROP TABLE IF EXISTS `tb_binmatch`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tb_binmatch` (
  `basedir` varchar(256) DEFAULT NULL,
  `filename` varchar(256) DEFAULT NULL,
  `cpe` int(11) DEFAULT NULL,
  `fullmatch` int(11) DEFAULT NULL,
  `hostname` varchar(128) DEFAULT NULL,
  `userdefkey` varchar(256) DEFAULT NULL,
  KEY `binmatchidx` (`cpe`),
  KEY `hostnameidx` (`hostname`),
  KEY `userdefkeyidx` (`userdefkey`(255)),
  CONSTRAINT `tb_binmatch_ibfk_1` FOREIGN KEY (`cpe`) REFERENCES `tb_cpe` (`cpeid`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tb_cpe`
--

DROP TABLE IF EXISTS `tb_cpe`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tb_cpe` (
  `cpeid` int(11) NOT NULL AUTO_INCREMENT,
  `cpepart` char(1) DEFAULT NULL,
  `cpevendor` varchar(128) DEFAULT NULL,
  `cpeproduct` varchar(128) DEFAULT NULL,
  `cpeversion` varchar(128) DEFAULT NULL,
  `cpeupdate` varchar(128) DEFAULT NULL,
  `cpeedition` varchar(128) DEFAULT NULL,
  `cpelanguage` varchar(128) DEFAULT NULL,
  `cpeswedition` varchar(128) DEFAULT NULL,
  `cpetargetsw` varchar(128) DEFAULT NULL,
  `cpetargethw` varchar(128) DEFAULT NULL,
  `cpeother` varchar(128) DEFAULT NULL,
  PRIMARY KEY (`cpeid`),
  KEY `cpeidx` (`cpevendor`,`cpeproduct`)
) ENGINE=InnoDB AUTO_INCREMENT=104557 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tb_cpe_parents`
--

DROP TABLE IF EXISTS `tb_cpe_parents`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tb_cpe_parents` (
  `mastercpe` int(11) DEFAULT NULL,
  `childcpe` int(11) DEFAULT NULL,
  KEY `mastercpe` (`mastercpe`),
  KEY `childcpe` (`childcpe`),
  CONSTRAINT `tb_cpe_parents_ibfk_1` FOREIGN KEY (`mastercpe`) REFERENCES `tb_cpe` (`cpeid`) ON DELETE CASCADE,
  CONSTRAINT `tb_cpe_parents_ibfk_2` FOREIGN KEY (`childcpe`) REFERENCES `tb_cpe` (`cpeid`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tb_cpe_versions`
--

DROP TABLE IF EXISTS `tb_cpe_versions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tb_cpe_versions` (
  `cpeversion` varchar(255) NOT NULL,
  `f1` int(11) DEFAULT NULL,
  `f2` int(11) DEFAULT NULL,
  `f3` int(11) DEFAULT NULL,
  `f4` int(11) DEFAULT NULL,
  `f5` int(11) DEFAULT NULL,
  `f6` int(11) DEFAULT NULL,
  `f7` int(11) DEFAULT NULL,
  `f8` int(11) DEFAULT NULL,
  `f9` int(11) DEFAULT NULL,
  `f10` int(11) DEFAULT NULL,
  `f11` int(11) DEFAULT NULL,
  `f12` int(11) DEFAULT NULL,
  `f13` int(11) DEFAULT NULL,
  `f14` int(11) DEFAULT NULL,
  `f15` int(11) DEFAULT NULL,
  PRIMARY KEY (`cpeversion`),
  KEY `cpe_versions_idx` (`cpeversion`),
  KEY `cpe_versions_2_idx` (`f1`,`f2`,`f3`,`f4`,`f5`,`f6`,`f7`,`f8`,`f9`,`f10`,`f11`,`f12`,`f13`,`f14`,`f15`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tb_cve`
--

DROP TABLE IF EXISTS `tb_cve`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tb_cve` (
  `year` smallint(6) DEFAULT NULL,
  `sequence` int(11) DEFAULT NULL,
  `cpe` int(11) DEFAULT NULL,
  KEY `cveidx` (`year`,`sequence`),
  KEY `cveidx2` (`cpe`),
  CONSTRAINT `tb_cve_ibfk_1` FOREIGN KEY (`cpe`) REFERENCES `tb_cpe` (`cpeid`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tb_versionmatch`
--

DROP TABLE IF EXISTS `tb_versionmatch`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tb_versionmatch` (
  `filename` varchar(256) DEFAULT NULL,
  `filetype` smallint(6) DEFAULT NULL,
  `filematch` varchar(256) DEFAULT NULL,
  `contentmatch` varchar(128) DEFAULT NULL,
  `cpe` int(11) DEFAULT NULL,
  KEY `cpe` (`cpe`),
  KEY `vmidx` (`filename`(255)),
  CONSTRAINT `tb_versionmatch_ibfk_1` FOREIGN KEY (`cpe`) REFERENCES `tb_cpe` (`cpeid`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2011-04-12 21:25:06
