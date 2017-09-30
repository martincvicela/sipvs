<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:fo="http://www.w3.org/1999/XSL/Format">

<xsl:template match="/DogEvidenceRecord">
	<html>
		<body>
			<style>
				div {
					margin-bottom: 2%;
				} 
			</style>
			<div style="margin-left:10%; margin-right:50%; border:solid; border-width:1px">
				<div style="margin-left:5%;">
					<div>
						<h4 style="text-align:center;">Prihlásenie psov do evidencie</h4>
					</div>
					<xsl:call-template name="ContactInfo"/>
					<div>Zoznam psov:</div>
					<table style="margin-bottom:2%;" border="1">
						<tr>
							<th>Dátum narodenia</th>
							<th>Meno</th>
							<th>Plemeno</th>
							<th>Pohlavie</th>
							<th>Farba</th>
							<th>Evidenčné číslo psa (číslo známky)</th>
						</tr>
						<xsl:apply-templates select="Dog"/>
					</table>
					<div><xsl:value-of select="City"/> dňa <xsl:value-of select="RequestDate"/></div>
				</div>
			</div>
		</body>
	</html>
</xsl:template>

<xsl:template match="Dog">
	<tr>
		<td><xsl:value-of select="BirthDate"/></td>
		<td><xsl:value-of select="Name"/></td>
		<td><xsl:value-of select="attribute::Breed"/></td>
		<td><xsl:value-of select="attribute::Colour"/></td>
		<td><xsl:value-of select="attribute::Gender"/></td>
		<td><xsl:value-of select="EvidenceNumber"/></td>
	</tr>
</xsl:template>

<xsl:template name="ContactInfo">
	<div>Obchodné meno / meno a priezvisko vlastníka (držiteľa) psa: <xsl:value-of select="Name"/></div>
	<div>
		<div>Kontakt: <span style="padding:30px"></span> telefón <span style="padding:35px"></span><xsl:value-of select="//TelephoneNumber"/></div>	
		<div style="margin-left:120px;"> e-mail <span style="padding:36px"></span> <xsl:value-of select="//Email"/></div>
	</div>
</xsl:template>

</xsl:stylesheet>
