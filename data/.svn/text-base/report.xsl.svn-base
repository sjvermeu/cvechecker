<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
                xmlns:exsl="http://exslt.org/common"
                xmlns:str="http://exslt.org/strings"
                xmlns:fn="http://www.w3.org/2005/02/xpath-functions"
                xmlns:random="http://exslt.org/random"
                extension-element-prefixes="exsl"
                version="1.0">

<xsl:output encoding="UTF-8" method="html" indent="yes" doctype-public="-//W3C//DTD HTML 4.01 Transitional//EN" doctype-system="http://www.w3.org/TR/html4/loose.dtd"/>

<xsl:param name="acknowledgements" />

<!--
  Main template, selects home versus other pages
-->
<xsl:template match="records">
<html>
<head>
<title>CSV Report</title>
</head>
<body>
<!-- Loop over vendors -->
<table>
<tr>
  <th>File</th><th>CPE</th><th>CVE</th><th>Action</th>
</tr>
<xsl:for-each select="//record[not(CPE=preceding-sibling::record/CPE)]/CPE">
  <xsl:sort key="text()" />
  <xsl:variable name="cpe" select="." />
  <xsl:for-each select="//record[CPE=$cpe][not(File=preceding-sibling::record[CPE=$cpe]/File)]/File">
    <xsl:sort key="text()" />
    <xsl:variable name="file" select="." />
    <xsl:for-each select="//record[CPE=$cpe][File=$file]/CVE">
      <xsl:sort key="text()" />
      <xsl:variable name="cve" select="." />
      <xsl:variable name="action" select="document($acknowledgements)/acknowledgements/file[@name=$file][@cve=$cve]/@action" />
      <xsl:variable name="output"><xsl:choose><xsl:when test="$action"><xsl:value-of select="$action" /></xsl:when><xsl:otherwise>new</xsl:otherwise></xsl:choose></xsl:variable>
      <xsl:variable name="style"><xsl:choose><xsl:when test="$output='new'">color: red;</xsl:when><xsl:when test="$output='irrelevant'">color: gray;</xsl:when><xsl:otherwise>color: black;</xsl:otherwise></xsl:choose></xsl:variable>
<tr style="{$style}">
  <td><xsl:value-of select="$file" /></td>
  <td><xsl:value-of select="$cpe" /></td>
  <td><xsl:value-of select="$cve" /></td>
  <td>
    <xsl:choose>
      <xsl:when test="$action"><xsl:value-of select="$action" /></xsl:when>
      <xsl:otherwise>new</xsl:otherwise>
    </xsl:choose>
  </td>
</tr>
    </xsl:for-each>
  </xsl:for-each>
</xsl:for-each>
</table>
</body>
</html>
</xsl:template>

</xsl:stylesheet>
