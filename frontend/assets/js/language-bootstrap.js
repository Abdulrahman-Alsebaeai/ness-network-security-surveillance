/* Apply the saved UI language before the page paints to avoid LTR/RTL flicker. */
(function(){
  let language = 'en';
  try{
    const saved = localStorage.getItem('ness_language');
    if(saved === 'ar' || saved === 'en') language = saved;
  }catch(_){ }
  document.documentElement.lang = language;
  document.documentElement.dir = language === 'ar' ? 'rtl' : 'ltr';
})();
