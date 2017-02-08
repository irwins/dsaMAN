Function New-ADMUser{
   [CmdletBinding()]
   param(
      [String]$Identity,

      [PSCustomObject]$Properties
   )

   Process{
      if($PSBoundParameters.ContainsKey('Identity')){
         if($PSBoundParameters.ContainsKey('Properties')){
            Write-Verbose "PSBoundParameter Identity & Properties"
            return [ADMUser]::new($Identity,$Properties) 
         }
         else{
            Write-Verbose "PSBoundParameter Identity only"
            return [ADMUser]::new($Identity)
         }
      }
      else{
         Write-Verbose 'No PSBoundParameter'
         return [ADMUser]::new()
      }
   }
}