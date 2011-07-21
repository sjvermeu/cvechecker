<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
                xmlns:nvd="http://scap.nist.gov/schema/feed/vulnerability/2.0"
		xmlns:vuln="http://scap.nist.gov/schema/vulnerability/0.4" version="1.0">

<xsl:output encoding="UTF-8" method="text" />

<xsl:template match="/"><xsl:apply-templates select="nvd:nvd" /></xsl:template>

<xsl:template match="nvd:nvd"><xsl:apply-templates select="nvd:entry" /></xsl:template>

<xsl:template match="nvd:entry">
<xsl:apply-templates select="vuln:vulnerable-software-list">
  <xsl:with-param name="entryid" select="@id" />
</xsl:apply-templates>
</xsl:template>

<xsl:template match="vuln:vulnerable-software-list">
<xsl:param name="entryid" />
<xsl:for-each select="vuln:product">
<xsl:value-of select="$entryid" />:<xsl:value-of select="text()" /><xsl:text>
</xsl:text>
</xsl:for-each>
</xsl:template>

</xsl:stylesheet>
