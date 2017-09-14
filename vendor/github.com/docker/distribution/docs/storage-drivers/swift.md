<!--[metadata]>
+++
title = "Swift storage driver"
description = "Explains how to use the OpenStack swift storage driver"
keywords = ["registry, service, driver, images, storage,  swift"]
[menu.main]
parent="smn_storagedrivers"
+++
<![end-metadata]-->


# OpenStack Swift storage driver

An implementation of the `storagedriver.StorageDriver` interface that uses [OpenStack Swift](http://docs.openstack.org/developer/swift/) for object storage.

## Parameters


<table>
  <tr>
    <th>Parameter</th>
    <th>Required</th>
    <th>Description</th>
  </tr>
  <tr>
    <td>
      <code>authurl</code>
    </td>
    <td>
      yes
    </td>
    <td>
      URL for obtaining an auth token. https://storage.myprovider.com/v2.0 or https://storage.myprovider.com/v3/auth
    </td>
  </tr>
  <tr>
    <td>
      <code>username</code>
    </td>
    <td>
      yes
    </td>
    <td>
      Your Openstack user name.
    </td>
  </tr>
  <tr>
    <td>
      <code>password</code>
    </td>
    <td>
      yes
    </td>
    <td>
      Your Openstack password.
    </td>
  </tr>
  <tr>
    <td>
      <code>region</code>
    </td>
    <td>
      no
    </td>
    <td>
      The Openstack region in which your container exists.
    </td>
  </tr>
  <tr>
    <td>
      <code>container</code>
    </td>
    <td>
      yes
    </td>
    <td>
      The name of your Swift container where you wish to store the registry's data. The driver creates the named container during its initialization.
    </td>
  </tr>
  <tr>
    <td>
      <code>tenant</code>
    </td>
    <td>
      no
    </td>
    <td>
      Your Openstack tenant name. You can either use <code>tenant</code> or <code>tenantid</code>.
    </td>
  </tr>
  <tr>
    <td>
      <code>tenantid</code>
    </td>
    <td>
      no
    </td>
    <td>
      Your Openstack tenant id. You can either use <code>tenant</code> or <code>tenantid</code>.
    </td>
  </tr>
  <tr>
    <td>
      <code>domain</code>
    </td>
    <td>
      no
    </td>
    <td>
      Your Openstack domain name for Identity v3 API. You can either use <code>domain</code> or <code>domainid</code>.
    </td>
  </tr>
  <tr>
    <td>
      <code>domainid</code>
    </td>
    <td>
      no
    </td>
    <td>
      Your Openstack domain id for Identity v3 API. You can either use <code>domain</code> or <code>domainid</code>.
    </td>
  </tr>
  <tr>
    <td>
      <code>trustid</code>
    </td>
    <td>
      no
    </td>
    <td>
      Your Openstack trust id for Identity v3 API.
    </td>
  </tr>
  <tr>
    <td>
      <code>insecureskipverify</code>
    </td>
    <td>
      no
    </td>
    <td>
      true to skip TLS verification, false by default.
    </td>
  </tr>
  <tr>
    <td>
      <code>chunksize</code>
    </td>
    <td>
      no
    </td>
    <td>
      Size of the data segments for the Swift Dynamic Large Objects. This value should be a number (defaults to 5M).
    </td>
  </tr>
  <tr>
    <td>
      <code>prefix</code>
    </td>
    <td>
      no
    </td>
    <td>
      This is a prefix that will be applied to all Swift keys to allow you to segment data in your container if necessary. Defaults to the empty string which is the container's root.
    </td>
  </tr>
  <tr>
    <td>
      <code>secretkey</code>
    </td>
    <td>
      no
    </td>
    <td>
      The secret key used to generate temporary URLs.
    </td>
  </tr>
  <tr>
    <td>
      <code>accesskey</code>
    </td>
    <td>
      no
    </td>
    <td>
      The access key to generate temporary URLs. It is used by HP Cloud Object Storage in addition to the `secretkey` parameter.
    </td>
  </tr>
  <tr>
    <td>
      <code>authversion</code>
    </td>
    <td>
      no
    </td>
    <td>
      Specify the OpenStack Auth's version,for example <code>3</code>. By default the driver will autodetect the auth's version from the AuthURL.
    </td>
  </tr>
  <tr>
    <td>
      <code>endpointtype</code>
    </td>
    <td>
      no
    </td>
    <td>
      The endpoint type used when connecting to swift. Possible values are `public`, `internal` and `admin`. Default is `public`.
    </td>
  </tr>
</table>

The features supported by the Swift server are queried by requesting the `/info` URL on the server. In case the administrator
disabled that feature, the configuration file can specify the following optional parameters :

<table>
<tr>
    <td>
    <code>tempurlcontainerkey</code>
    </td>
    <td>
    <p>
    Specify whether to use container secret key to generate temporary URL when set to true, or the account secret key otherwise.</p>
    </p>
    </td>
</tr>
<tr>
    <td>
    <code>tempurlmethods</code>
    </td>
    <td>
    <p>
    Array of HTTP methods that are supported by the TempURL middleware of the Swift server. Example:</p>
    <code>
    - tempurlmethods:
      - GET
      - PUT
      - HEAD
      - POST
      - DELETE
    </code>
    </p>
    </td>
</tr>
</table>
