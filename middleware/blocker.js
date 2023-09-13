const Netmask = require('netmask').Netmask;

exports.preventCiscoRequest = (req, res, next) => {
  
  // Fix for local IP
  if (req.ip == '::1') {
    return next();
  }
  
  // CIDRs for Cisco Umbrella, see https://support.umbrella.com/hc/en-us/articles/360059292052-Additional-Egress-IP-Address-Range
  // Also adds CIDRs for 365 Defender SafeLinks scanner, see https://learn.microsoft.com/nl-nl/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide
  const cidrs = ['146.112.0.0/16', '155.190.0.0/16', '151.186.0.0/16', '40.90.0.0/15', '40.92.0.0/15', '40.94.0.0/16', '40.107.0.0/16', '52.100.0.0/14', '52.238.78.88/32', '104.47.0.0/17', '13.107.6.152/31', '13.107.18.10/31', '13.107.128.0/22', '23.103.160.0/20', '40.96.0.0/13', '40.104.0.0/15', '52.96.0.0/14', '131.253.33.215/32', '132.245.0.0/16', '150.171.32.0/22', '204.79.197.215/32'];
  
  // Check if IP is in cidr
  const isIpInCidr = cidrs.some(cidr => {
    const block = new Netmask(cidr);
    return block.contains(req.ip);
  });
  
  if (!isIpInCidr) {
    return next();
  }
  
  console.log('IP is in CIDRs to block', req.ip, cidrs, isIpInCidr);
  
  req.flash('error', {msg: 'De url is geen geldige login url, wellicht is deze verlopen'});
  return res.redirect(`/auth/url/login?clientId=${req.query.clientId}`);
  
}
