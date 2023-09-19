const Netmask = require('netmask').Netmask;

exports.preventCiscoRequest = (req, res, next) => {
  
  // Fix for local IP
  if (req.ip == '::1') {
    return next();
  }
  
  // CIDRs for Cisco Umbrella
  // See https://support.umbrella.com/hc/en-us/articles/360059292052-Additional-Egress-IP-Address-Range
  // Also adds CIDRs for 365 Defender SafeLinks scanner ~(40.90.x.x - 40.94.x.x)
  const cidrs = ['146.112.0.0/16', '155.190.0.0/16', '151.186.0.0/16', '40.90.0.0/15', '40.92.0.0/15', '40.94.0.0/16'];
  
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
