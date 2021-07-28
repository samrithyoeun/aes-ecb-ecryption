//
//  ViewController.m
//  aes-ebc-encryption
//
//  Created by Samrith Yoeun on 7/28/21.
//

#import "ViewController.h"
#import "CryptLib.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
  [super viewDidLoad];
  
  [self startDecryption];
  
}

-(void)startDecryption {
  NSString *data = @"Qzh90TzUih3734zDdHcBKA==";
  NSString *key = @"6501ebc09db6634a";
  
  NSData *cryptData = [[NSData alloc]initWithBase64EncodedString:data options:NSDataBase64DecodingIgnoreUnknownCharacters];
  
  StringEncryption *crypt = [StringEncryption new];
  NSString *result = [crypt decrypt:cryptData key:key];
  NSLog(@"--- result : %@", result);
}


@end
