<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
                xmlns:nvd="http://scap.nist.gov/schema/feed/vulnerability/2.0"
		xmlns:vuln="http://scap.nist.gov/schema/vulnerability/0.4" 
		xmlns:cvss="http://scap.nist.gov/schema/cvss-v2/0.2" version="1.0">

<xsl:output encoding="UTF-8" method="text" />

<xsl:template match="/"><xsl:apply-templates select="nvd:nvd" /></xsl:template>

<xsl:template match="nvd:nvd"><xsl:apply-templates select="nvd:entry" /></xsl:template>

<xsl:template match="nvd:entry">
<xsl:variable name="entrycvss" select="vuln:cvss/cvss:base_metrics/cvss:score" />
<xsl:apply-templates select="vuln:vulnerable-software-list">
  <xsl:with-param name="entryid" select="@id" />
  <xsl:with-param name="entrycvss" select="$entrycvss" />
</xsl:apply-templates>
</xsl:template>

<xsl:template match="vuln:vulnerable-software-list">
<xsl:param name="entryid" />
<xsl:param name="entrycvss" />
<xsl:for-each select="vuln:product">
<xsl:value-of select="$entryid" />:<xsl:value-of select="$entrycvss" />:<xsl:value-of select="text()" /><xsl:text>
</xsl:text>
</xsl:for-each>
</xsl:template>

</xsl:stylesheet>
