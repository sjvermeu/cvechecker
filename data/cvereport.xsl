<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
                version="1.0">

<xsl:output method="xml" indent="yes" encoding="UTF-8"/>
<xsl:key name="cpes" match="CPE" use="text()" />

<xsl:template match="records">
<html xmlns="http://www.w3.org/1999/xhtml">
  <head>
    <title>cvechecker report</title>
    <link rel="stylesheet" href="report.css" type="text/css" media="screen" />
  </head>
  <body>
<h1>cvechecker report</h1>

<xsl:call-template name="newdetected" />

  </body>
</html>
</xsl:template>

<xsl:template name="newdetected">

<h2>New CVE Matches</h2>

<xsl:choose>
  <xsl:when test="count(//record[not(CVE=document('acknowledgements.xml')/acknowledgements/file/@cve)]) = 0">
    <p>No new CVE entries matching your current system.</p>
  </xsl:when>
  <xsl:otherwise>

<p>
The following table lists new CVE entries that potentially affect your system. None of these
CVE entries have been previously found on your system (or you failed to acknowledge them).
</p>


<table>
<tr>
  <th>CVE number</th>
  <th>CVSS Score</th>
  <th>Application (CPE code)</th>
</tr>
<xsl:for-each select="//record[not(CVE=document('acknowledgements.xml')/acknowledgements/file/@cve)][not(CVE=preceding-sibling::record/CVE)]">
  <xsl:variable name="cveid" select="CVE" />
  <xsl:variable name="cpeid" select="CPE" />
  <xsl:variable name="cvss" select="CVSS" />
  <tr>
    <td><a href="http://www.cvedetails.com/cve-details.php?cve_id={$cveid}"><xsl:value-of select="$cveid" /></a></td>
    <td><xsl:value-of select="$cvss" /></td>
    <td><xsl:value-of select="$cpeid" /></td>
  </tr>
</xsl:for-each>
</table>
  </xsl:otherwise>
</xsl:choose>

<h2>Newly Vulnerable Files</h2>

<p>
The following table lists the files that have one (or more) CVE entries attached to them, but have
yet to be acknowledged by you.
</p>

<table>
  <tr>
    <th>File</th>
    <th>Parent Application(s)</th>
    <th>Affected, unacknowledged CVE entries</th>
    <th>CVSS Score</th>
  </tr>
  <xsl:for-each select="//record[not(File=document('acknowledgements.xml')/acknowledgements/file/@name)][not(File=preceding-sibling::record/File)]">
    <xsl:variable name="fileid" select="File" />
    <xsl:for-each select="//record[File=$fileid][not(CVE=document('acknowledgements.xml')/acknowledgements/file[@name=$fileid]/@cve)][not(CVE=preceding-sibling::record[File=$fileid]/CVE)]">
      <xsl:variable name="cpeid" select="CPE" />
      <xsl:variable name="cvss" select="CVSS" />
      <xsl:variable name="cveid" select="CVE" />
      <tr>
        <td><xsl:value-of select="$fileid" /></td>
	<td><xsl:value-of select="$cpeid" /></td>
	<td><a href="http://www.cvedetails.com/cve-details.php?cve_id={$cveid}"><xsl:value-of select="$cveid" /></a></td>
	<td><xsl:value-of select="$cvss" /></td>
      </tr>
    </xsl:for-each>
  </xsl:for-each>
</table>

<h2>Acknowledged Vulnerabilities</h2>

<p>
The following table lists the files of which a CVE match is acknowledged and is pending investigation or
pending resolution.
</p>

<table>
  <tr>
    <th>File</th>
    <th>Parent Application</th>
    <th>CVE</th>
    <th>CVSS</th>
    <th>Comment</th>
  </tr>
  <xsl:for-each select="//record[not(CPE=preceding-sibling::record/CPE)]/CPE">
    <xsl:variable name="cpeid" select="." />
    <xsl:for-each select="//record[CPE=$cpeid][not(File=preceding-sibling::record[CPE=$cpeid]/File)]/File">
      <xsl:variable name="fileid" select="." />
      <xsl:variable name="cvss" select="ancestor::record/CVSS" />
      <xsl:for-each select="document('acknowledgements.xml')/acknowledgements/file[@name=$fileid][@state='acknowledged']">
        <xsl:variable name="commentid" select="@comment" />
	<xsl:variable name="cveid" select="@cve" />
        <tr>
	  <td><xsl:value-of select="$fileid" /></td>
	  <td><xsl:value-of select="$cpeid" /></td>
	  <td><a href="http://www.cvedetails.com/cve-details.php?cve_id={$cveid}"><xsl:value-of select="@cve" /></a></td>
	  <td><xsl:value-of select="$cvss" /></td>
	  <xsl:choose>
	    <xsl:when test="$commentid">
              <td><xsl:value-of select="//comment[@id=$commentid]" /></td>
	    </xsl:when>
	    <xsl:otherwise><td /></xsl:otherwise>
	  </xsl:choose>
	</tr>
      </xsl:for-each>
    </xsl:for-each>
  </xsl:for-each>
</table>

<h2>Irrelevant Vulnerabilities</h2>

<p>
The following table lists the files of which a CVE match is acknowledged and deemed resolved (for instance, 
a patch is deployed or a workaround is implemented that removes the exploitation risk).
</p>

<table>
  <tr>
    <th>File</th>
    <th>Parent Application</th>
    <th>CVE</th>
    <th>CVSS</th>
    <th>Comment</th>
  </tr>
  <xsl:for-each select="//record[not(CPE=preceding-sibling::record/CPE)]/CPE">
    <xsl:variable name="cpeid" select="." />
    <xsl:for-each select="//record[CPE=$cpeid][not(File=preceding-sibling::record[CPE=$cpeid]/File)]/File">
      <xsl:variable name="fileid" select="." />
      <xsl:variable name="cvss" select="ancestor::record/CVSS" />
      <xsl:for-each select="document('acknowledgements.xml')/acknowledgements/file[@name=$fileid][@state='irrelevant']">
        <xsl:variable name="resolutionid" select="@resolution" />
	<xsl:variable name="cveid" select="@cve" />
        <tr>
	  <td><xsl:value-of select="$fileid" /></td>
	  <td><xsl:value-of select="$cpeid" /></td>
	  <td><a href="http://www.cvedetails.com/cve-details.php?cve_id={$cveid}"><xsl:value-of select="@cve" /></a></td>
	  <td><xsl:value-of select="$cvss" /></td>
	  <xsl:choose>
	    <xsl:when test="$resolutionid">
              <td><xsl:value-of select="//resolution[@id=$resolutionid]" /></td>
	    </xsl:when>
	    <xsl:otherwise><td /></xsl:otherwise>
	  </xsl:choose>
	</tr>
      </xsl:for-each>
    </xsl:for-each>
  </xsl:for-each>
</table>

<h2>Deprecated Acknowledgements</h2>

<xsl:choose>
  <xsl:when test="count(document('acknowledgements.xml')/acknowledgements/file[not(@name=document('cvechecker.xml')/records/record/File)]) = 0">
    <p>No deprecated acknowledgements detected.</p>
  </xsl:when>
  <xsl:otherwise>
<p>
The following table lists the acknowledgements that are not part of your cvechecker report anymore.
This is most likely because the application has been upgraded or removed from your system, or removed
from the visibility of the cvechecker application.
</p>

<table>
  <tr>
    <th>File</th>
    <th>CVE</th>
    <th>State</th>
    <th>Comment</th>
  </tr>
  <xsl:for-each select="document('acknowledgements.xml')/acknowledgements/file[not(@name=document('cvechecker.xml')/records/record/File)]">
    <xsl:variable name="commentid" select="@comment" />
    <xsl:variable name="resolutionid" select="@resolution" />
    <xsl:variable name="cveid" select="@cve" />
  <tr>
    <td><xsl:value-of select="@name" /></td>
    <td><a href="http://www.cvedetails.com/cve-details.php?cve_id={$cveid}"><xsl:value-of select="@cve" /></a></td>
    <td><xsl:value-of select="@state" /></td>
    <xsl:choose>
      <xsl:when test="@comment">
        <td><xsl:value-of select="//comment[@id=$commentid]" /></td>
      </xsl:when>
      <xsl:when test="@resolution">
        <td><xsl:value-of select="//resolution[@id=$resolutionid]" /></td>
      </xsl:when>
      <xsl:otherwise>
        <td />
      </xsl:otherwise>
    </xsl:choose>
  </tr>
  </xsl:for-each>
</table>
  </xsl:otherwise>
</xsl:choose>


</xsl:template>
</xsl:stylesheet>

