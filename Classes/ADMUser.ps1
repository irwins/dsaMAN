Class ADMHelper{
   [String]$Identity

   ADMHelper(){}

   [HashTable] Splat([PSObject]$objProperties){
      $splat = @{}

      $objProperties | 
      Get-Member -MemberType *Property |
      ForEach-Object{
            $splat.$($_.Name) = $objProperties.$($_.Name)
      }

      return $splat
   }
}

Class ADMUser : ADMHelper{
   [String]$exportFolder = 'C:\scripts\export\dsa'
   [PSObject]$Properties
   [PSObject]$ValidationResults
   [PSObject[]]$ActionHistory
   Hidden [Boolean]$Exists

   #Default constuctor
   ADMUser(){}
   
   ADMUser([String]$id){
      $this.Identity = $id
   
      #Verify if account exists
      try{
         $this.Properties = Get-ADUser -Identity $this.Identity
         $this.Exists     = $true

         $Tags = @('Found','ADUser','Properties','Default')
         $MessageData = "ADUser $($this.Identity) found"
         $this.ActionHistory += Write-Information -MessageData $MessageData 6>&1 -Tags $Tags | Select-Object *  
      }
      catch{
         $this.Exists = $false

         $Tags = @('NotFound','ADUser','Properties','Default')
         $MessageData = "ADUser $($this.Identity) not found"
         $this.ActionHistory += Write-Information -MessageData $MessageData 6>&1 -Tags $Tags | Select-Object *  
      }
   }

   ADMUser([String]$id,[PSCustomObject]$userProperties){
      $this.Identity = $id
      $Tags = @('Found','ADUser','Properties')

      #Verify if account exists
      try{
         #Remove Properties not relevant
         $SelectProperties = ($UserProperties | Get-Member -MemberType NoteProperty).Name -ne @('Path')

         $this.Properties = Get-ADUser -Identity $this.Identity -Properties $SelectProperties
         $this.Exists     = $true

         $MessageData = "ADUser $($this.Identity) found"
         $this.ActionHistory += Write-Information -MessageData $MessageData 6>&1 -Tags $Tags | Select-Object *  
      }
      catch{
         $this.Exists     = $false
         $this.Properties = $userProperties

         $MessageData = "Error retrievingADUser $($this.Identity) properties"
         $this.ActionHistory += Write-Information -MessageData $MessageData 6>&1 -Tags $Tags | Select-Object *  
      }
   }

   GetProperties($UserProperties){
      if($this.Exists){
         #Remove Properties not relevant
         $UserProperties = $UserProperties -ne @('Path')
         $Tags =@('Get','ADUser','Properties','Specific')

         $this.Properties = Get-ADUser -Identity $this.Identity -Properties $UserProperties

         $MessageData = "Retrieving ADUser $($this.Identity) Properties: $($UserProperties -join ', ')"
         $this.ActionHistory += Write-Information -MessageData $MessageData 6>&1 -Tags $Tags | Select-Object *
      }
   }

   SetProperties($UserProperties){
      if($this.Exists){
         #Create Hashtable for splatting
         $paramSetProperties = @{}

         $splat = $this.Splat($userProperties)

         #Remove offending Parameters
         $splat.Keys |
         ForEach-Object{
            switch ($_) {
               'Path' {}
               'SamAccountName' {}
               'Name' {}
               Default {$paramSetProperties.$($_) = $(@{$true = $null ; $false =$splat.$_}[[string]::isNullOrEmpty($splat.$_)])}
            }
         }

         Set-ADUser -Identity $this.Identity @paramSetProperties

         $Tags = @('Set','ADUser','Properties','Success')
         $MessageData = "Setting ADUser $($this.Identity) Properties: $( $paramSetProperties.Keys -join ', ')"
         $this.ActionHistory += Write-Information -MessageData $MessageData 6>&1 -Tags $Tags | Select-Object *
      }
   }

   Clear($UserProperties){
      if($this.Exists){
         #Create Hashtable for splatting
         $paramClearProperties = @{}

         #Remove offending Parameters
         $userProperties |
         ForEach-Object{
            switch ($_) {
               'Path' {}
               'SamAccountName' {}
               'Name' {}
               Default {$paramClearProperties.$($_) = $null}
            }
         }

         Set-ADUser -Identity $this.Identity @paramClearProperties

         $Tags = @('Clear','ADUser','Properties','Success')
         $MessageData = "Clearing ADUser $($this.Identity) Properties: $( $userProperties -join ', ')"
         $this.ActionHistory += Write-Information -MessageData $MessageData 6>&1 -Tags $Tags | Select-Object *
      }
   }

   Create(){
      if(!($this.Exists)){
         $userParams = $this.Splat($this.Properties)
         $userProperties = ($this.Properties | Get-Member -MemberType *Property).Name

         try{
            New-ADUser @userParams

            $Tags = @('Create','ADUser','Properties','Specific','Success')
            $MessageData = "Creating ADUser $($this.Identity) Properties: $( $userProperties -join ', ')"
            $this.ActionHistory += Write-Information -MessageData $MessageData 6>&1 -Tags $Tags | Select-Object *

            $this.Exists = $true
            
            #Update user properties now that it exists
            $this.GetProperties($userProperties)
         }
         catch{
            $Tags = @('Create','ADUser','Properties','Specific','Failed')
            $MessageData = "Creating ADUser $($this.Identity) failed"
            $this.ActionHistory += Write-Information -MessageData $MessageData 6>&1 -Tags $Tags | Select-Object *
         }
      }
   }

   Enable(){
      if($this.Exists){
         Enable-ADAccount -Identity $this.Identity
         
         $Tags = @('Enable','ADUser')
         $MessageData = "Enabled ADUser $($this.Identity)"
         $this.ActionHistory += Write-Information -MessageData $MessageData 6>&1 -Tags $Tags | Select-Object *
      }
   }

   Disable(){
      if($this.Exists){
         Disable-ADAccount -Identity $this.Identity

         $Tags = @('Disable','ADUser')
         $MessageData = "Disabled ADUser $($this.Identity)"
         $this.ActionHistory += Write-Information -MessageData $MessageData 6>&1 -Tags $Tags | Select-Object *
      }
   }

   UnLock(){
      if($this.Exists){
         Unlock-ADAccount -Identity $this.Identity

         $Tags = @('Unlock','ADUser')
         $MessageData = "Unlocked ADUser $($this.Identity)"
         $this.ActionHistory += Write-Information -MessageData $MessageData 6>&1 -Tags $Tags | Select-Object *
      }
   }

   Move($targetPath){
      if($this.Exists){
         Move-ADObject -Identity (Get-ADUser $this.Identity).DistinguishedName -TargetPath $targetPath

         $Tags = @('Move','ADUser')
         $MessageData = "Saving ADUser $($this.Identity) Snapshot"
         $this.ActionHistory += Write-Information -MessageData $MessageData 6>&1 -Tags $Tags | Select-Object *
      }
   }

   ResetPassword($password){
      if($this.Exists){
         Set-ADAccountPassword $this.Identity -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $password -Force)

         $Tags = @('Reset','ADUser','Password')
         $MessageData = "Resetting ADUser $($this.Identity) password"
         $this.ActionHistory += Write-Information -MessageData $MessageData 6>&1 -Tags $Tags | Select-Object *
      }
   }

   RunValidation($src,$props,$save){
      #Get Current user properties
      $this.GetProperties($props)
      $tgt = $this.Properties

      if($this.Exists){
         $Tags = @('Validation','ADUser')
         $MessageData = "Validating AD User properties $($src.Name)"
         $this.ActionHistory += Write-Information -MessageData $MessageData 6>&1 -Tags $Tags | Select-Object *

         $sbValidation = {
            param($Source,$Target,$Properties)
            Describe "AD User operational readiness for $($Source.Name)" {
               Context 'Verifying ADUser Attributes'{
                  ForEach($property in $Properties){

                     if(($property -eq 'Path') -and (![String]::IsNullOrEmpty($Source.$property))){
                        it "User is located in $($Source.$property)" {
                           $Target.DistinguishedName.Contains($Source.$property) | Should -Be $true
                        }
                     }
                     else{
                        it "User property $($property) value is $($Target.$property)" {
                           $Source.$property | Should -Be $Target.$property
                        }
                     }
                  }
               }
            }
         }

         $pesterFile = "$($this.exportFolder)\ADUser.tests.ps1"
         $sbValidation.ToString() | out-file -FilePath $pesterFile -Force

         $testADUser = @(
            @{ 
               Path = $pesterFile
               Parameters = @{ 
                  Source     = $src
                  Target     = $tgt
                  Properties = $props
               } 
            }
         )

         if($save){
            $this.ValidationResults = [PSCustomObject]@{
               ValidationDate = $(Get-Date)
               Results = Invoke-Pester -Path $testADUser -PassThru
            }
         }
         else{
            Invoke-Pester -Path $testADUser
         }
      }
      else{
         $Tags = @('Validation','ADUser','NotFound')
         $MessageData = "Validation error. User $($this.Identity) not found"
         $this.ActionHistory += Write-Information -MessageData $MessageData 6>&1 -Tags $Tags | Select-Object *
      }
   }
}

