<?xml version="1.0" encoding="UTF-8"?>
<!-- Minimal sample substation configuration for SenseL lab/tests.
     One relay IED (server, GOOSE publisher) and one HMI/client. -->
<SCL xmlns="http://www.iec.ch/61850/2003/SCL">
  <Header id="SenseL-Lab-Substation" version="1"/>
  <Communication>
    <SubNetwork name="StationBus" type="8-MMS">
      <ConnectedAP iedName="ied-01" apName="AP1">
        <Address>
          <P type="IP">192.168.10.50</P>
          <P type="IP-SUBNET">255.255.255.0</P>
        </Address>
        <GSE ldInst="LD0" cbName="gcbEvents">
          <Address>
            <P type="MAC-Address">01-0C-CD-01-00-01</P>
            <P type="APPID">03E8</P>
            <P type="VLAN-ID">005</P>
            <P type="VLAN-PRIORITY">4</P>
          </Address>
          <MinTime unit="s" multiplier="m">4</MinTime>
          <MaxTime unit="s" multiplier="m">2000</MaxTime>
        </GSE>
      </ConnectedAP>
      <ConnectedAP iedName="hmi-01" apName="AP1">
        <Address>
          <P type="IP">192.168.10.10</P>
        </Address>
      </ConnectedAP>
    </SubNetwork>
  </Communication>
  <IED name="ied-01">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_0">
            <GSEControl name="gcbEvents" appID="SenseL/LD0/LLN0/gcbEvents" datSet="Events" confRev="1" type="GOOSE"/>
            <DataSet name="Events"/>
          </LN0>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <IED name="hmi-01">
    <AccessPoint name="AP1"/>
  </IED>
</SCL>
