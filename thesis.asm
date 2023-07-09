.SECTION/DM vars;

.var p = b#100011011;

.VAR/CIRC Cipher_key [16] =  0x2b,0x28,0xab,0x09,
							 0x7e,0xae,0xf7,0xcf,
							 0x15,0xd2,0x15,0x4f,
							 0x16,0xa6,0x88,0x3c;

							 
.VAR/CIRC round_key_buffer [16] = 	 0,0,0,0,
									 0,0,0,0,
									 0,0,0,0,
									 0,0,0,0;
									 
.VAR/CIRC round_key_1 [16] =		 0,0,0,0,
									 0,0,0,0,
									 0,0,0,0,
									 0,0,0,0;
									 				 
.VAR/CIRC round_key_2 [16] = 	 	 0,0,0,0,
									 0,0,0,0,
									 0,0,0,0,
									 0,0,0,0;
									 
.VAR/CIRC round_key_3 [16] = 	 	 0,0,0,0,
									 0,0,0,0,
									 0,0,0,0,
									 0,0,0,0;

.VAR/CIRC round_key_4 [16] = 	 	 0,0,0,0,
									 0,0,0,0,
									 0,0,0,0,
									 0,0,0,0;

.VAR/CIRC round_key_5 [16] = 	 	 0,0,0,0,
									 0,0,0,0,
									 0,0,0,0,
									 0,0,0,0;

.VAR/CIRC round_key_6 [16] = 	 	 0,0,0,0,
									 0,0,0,0,
									 0,0,0,0,
									 0,0,0,0;

.VAR/CIRC round_key_7 [16] = 	 	 0,0,0,0,
									 0,0,0,0,
									 0,0,0,0,
									 0,0,0,0;

.VAR/CIRC round_key_8 [16] = 	 	 0,0,0,0,
									 0,0,0,0,
									 0,0,0,0,
									 0,0,0,0;
						

.VAR/CIRC round_key_9 [16] = 	 	 0,0,0,0,
									 0,0,0,0,
									 0,0,0,0,
									 0,0,0,0;

.VAR/CIRC round_key_10 [16] = 	 	 0,0,0,0,
									 0,0,0,0,
									 0,0,0,0,
									 0,0,0,0;
.VAR/CIRC BUFF  [4] = 0,0,0,0;

.VAR/CIRC BUFF1 [4] = 0,0,0,0;

/*.VAR/CIRC message [16] =	0x32,0x88,0x31,0xe0,
							0x43,0x5a,0x31,0x37,
							0xf6,0x30,0x98,0x07,
							0xa8,0x8d,0xa2,0x34;*/
							
.VAR/CIRC message [16] =  		0,0,0,0,
								0,0,0,0,
								0,0,0,0,
								0,0,0,0;
							
.VAR/CIRC MixColumns [16] =							
							0,0,0,0,
							0,0,0,0,
							0,0,0,0,
							0,0,0,0;
										
.VAR/CIRC matr[16] =		0x02,0x03,0x01,0x01,
							0x01,0x02,0x03,0x01,
							0x01,0x01,0x02,0x03,
							0x03,0x01,0x01,0x02;
				
.VAR/CIRC SubByte [16] = 		0,0,0,0,
						 		0,0,0,0,
						 		0,0,0,0,
						 		0,0,0,0;
					
.VAR/CIRC ShiftByte [16] =  	0,0,0,0,
								0,0,0,0,
								0,0,0,0,
								0,0,0,0;
							
//----------------------------------------------------------Sbox table----------------------------------------------//*							
//                 	  0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F   //*
.VAR/CIRC B[256] =	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0 
        			0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
        			0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
        			0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
        			0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
        			0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
        			0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
        			0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
        			0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
        			0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
        			0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
        			0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
        			0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
        			0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
        			0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
        			0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16; //F
//------------------------------------------------------------------------------------------------------------------//*
.SECTION/PM program;
	jump start;rti; rti; rti;
    rti; rti; rti; rti; 
    rti; rti; rti; rti; 
    rti; rti; rti; rti; 
    rti; rti; rti; rti; 
    rti; rti; rti; rti; 
    rti; rti; rti; rti; 
    rti; rti; rti; rti; 
    rti; rti; rti; rti; 
    rti; rti; rti; rti; 
    rti; rti; rti; rti; 
    rti; rti; rti; rti; 

zacycl:
	jump zacycl;
start:
	call input;
	call Gen_Keys;
//-----Add cipher key-----//
	I1 = message;
	L1 = length (message);
	I2 = Cipher_key;
	L2 = length (Cipher_key);
	I3 = message;
	L3 = length (message);
	M1 = 1;
	cntr = 16;
	do add_1   until ce;
		ax0 = dm(I1,M1);
		ay0 = dm(I2,M1);
		ar = ax0 xor ay0;
add_1: dm(I3,M1) = ar; 	
//--------rounde 1-------//
	call subbyte;
	call shiftbyte;
	call mixcolumns;
	I1 = message;
	L1 = length (message);
	I2 = round_key_1;
	L2 = length (round_key_1);
	I3 = message;
	L3 = length (message);
	M1 = 1;
	cntr = 16;
	do add_2 until ce;
		ax0 = dm(I1,M1);
		ay0 = dm(I2,M1);
		ar = ax0 xor ay0;
add_2: dm(I3,M1)= ar; 
//-------rounde 2-------//
	call subbyte;
	call shiftbyte;
	call mixcolumns;
	I1 = message;
	L1 = length (message);
	I2 = round_key_2;
	L2 = length (round_key_2);
	I3 = message;
	L3 = length (message);
	M1 = 1;
	cntr = 16;
	do add_3 until ce;
		ax0 = dm(I1,M1);
		ay0 = dm(I2,M1);
		ar = ax0 xor ay0;
add_3: dm(I3,M1)= ar;
//--------rounde 3-------// 
	call subbyte;
	call shiftbyte;
	call mixcolumns;
		I1 = message;
	L1 = length (message);
	I2 = round_key_3;
	L2 = length (round_key_3);
	I3 = message;
	L3 = length (message);
	M1 = 1;
	cntr = 16;
	do add_4 until ce;
		ax0 = dm(I1,M1);
		ay0 = dm(I2,M1);
		ar = ax0 xor ay0;
add_4: dm(I3,M1)= ar;
//--------rounde 4-------// 
	call subbyte;
	call shiftbyte;
	call mixcolumns;
		I1 = message;
	L1 = length (message);
	I2 = round_key_4;
	L2 = length (round_key_4);
	I3 = message;
	L3 = length (message);
	M1 = 1;
	cntr = 16;
	do add_5 until ce;
		ax0 = dm(I1,M1);
		ay0 = dm(I2,M1);
		ar = ax0 xor ay0;
add_5: dm(I3,M1)= ar;
//--------rounde 5-------// 
	call subbyte;
	call shiftbyte;
	call mixcolumns;
		I1 = message;
	L1 = length (message);
	I2 = round_key_5;
	L2 = length (round_key_5);
	I3 = message;
	L3 = length (message);
	M1 = 1;
	cntr = 16;
	do add_6 until ce;
		ax0 = dm(I1,M1);
		ay0 = dm(I2,M1);
		ar = ax0 xor ay0;
add_6: dm(I3,M1)= ar;
//--------rounde 6-------// 
	call subbyte;
	call shiftbyte;
	call mixcolumns;
		I1 = message;
	L1 = length (message);
	I2 = round_key_6;
	L2 = length (round_key_6);
	I3 = message;
	L3 = length (message);
	M1 = 1;
	cntr = 16;
	do add_7 until ce;
		ax0 = dm(I1,M1);
		ay0 = dm(I2,M1);
		ar = ax0 xor ay0;
add_7: dm(I3,M1)= ar;
//--------rounde 7-------// 
	call subbyte;
	call shiftbyte;
	call mixcolumns;
		I1 = message;
	L1 = length (message);
	I2 = round_key_7;
	L2 = length (round_key_7);
	I3 = message;
	L3 = length (message);
	M1 = 1;
	cntr = 16;
	do add_8 until ce;
		ax0 = dm(I1,M1);
		ay0 = dm(I2,M1);
		ar = ax0 xor ay0;
add_8: dm(I3,M1)= ar;
//--------rounde 8-------// 
	call subbyte;
	call shiftbyte;
	call mixcolumns;
		I1 = message;
	L1 = length (message);
	I2 = round_key_8;
	L2 = length (round_key_8);
	I3 = message;
	L3 = length (message);
	M1 = 1;
	cntr = 16;
	do add_9 until ce;
		ax0 = dm(I1,M1);
		ay0 = dm(I2,M1);
		ar = ax0 xor ay0;
add_9: dm(I3,M1)= ar;
//--------rounde 9-------// 
	call subbyte;
	call shiftbyte;
	call mixcolumns;
		I1 = message;
	L1 = length (message);
	I2 = round_key_9;
	L2 = length (round_key_9);
	I3 = message;
	L3 = length (message);
	M1 = 1;
	cntr = 16;
	do add_10 until ce;
		ax0 = dm(I1,M1);
		ay0 = dm(I2,M1);
		ar = ax0 xor ay0;
add_10: dm(I3,M1)= ar;
//-------rounde 10--------//
	call subbyte;
	call shiftbyte;
	I1 = ShiftByte;
	L1 = length (ShiftByte);
	I2 = round_key_10;
	L2 = length (round_key_10);
	I3 = message;
	L3 = length (message);
	M1 = 1;
	cntr = 16;
	do add_11 until ce;
		ax0 = dm(I1,M1);
		ay0 = dm(I2,M1);
		ar = ax0 xor ay0;
add_11: Io(0) = ar;
call zacycl;
//-------------------------//
// genegeration round keys //
//-------------------------//
Gen_Keys:
//-------Cipher_key-------//
    I1 = round_key_buffer;
    L1 = length(round_key_buffer);
    I2 = Cipher_key;
    L2 = length(Cipher_key);
    M1 = 1;
    cntr = 16;
    do record_1 until ce;
    ar = dm(I2,M1);
record_1:    dm(I1,M1) = ar;
//---------Key 1---------//
    sr1 = 0x01;
	call RotWord;
	call Sbox;
	call Rcon;
	call Solve;
	I1 = round_key_buffer;
    L1 = length(round_key_buffer);
    I2 = round_key_1;
    L2 = length(round_key_1);
    M1 = 1;
    cntr = 16;
    do record_2 until ce;
    ar = dm(I1,M1);
record_2:    dm(I2,M1) = ar;
//---------Key 2---------//
	sr1 = 0x02;
	call RotWord;
	call Sbox;
	call Rcon;
	call Solve;
	I1 = round_key_buffer;
    L1 = length(round_key_buffer);
    I2 = round_key_2;
    L2 = length(round_key_2);
    M1 = 1;
    cntr = 16;
    do record_3 until ce;
    ar = dm(I1,M1);
record_3:    dm(I2,M1) = ar;
//---------Key 3---------//
	sr1 = 0x04;
	call RotWord;
	call Sbox;
	call Rcon;
	call Solve;
	I1 = round_key_buffer;
    L1 = length(round_key_buffer);
    I2 = round_key_3;
    L2 = length(round_key_3);
    M1 = 1;
    cntr = 16;
    do record_4 until ce;
    ar = dm(I1,M1);
record_4:    dm(I2,M1) = ar;
//---------Key 4---------//
	sr1 = 0x08;
	call RotWord;
	call Sbox;
	call Rcon;
	call Solve;
	I1 = round_key_buffer;
    L1 = length(round_key_buffer);
    I2 = round_key_4;
    L2 = length(round_key_4);
    M1 = 1;
    cntr = 16;
    do record_5 until ce;
    ar = dm(I1,M1);
record_5:    dm(I2,M1) = ar;
//---------Key 5---------//
	sr1 = 0x10;
	call RotWord;
	call Sbox;
	call Rcon;
	call Solve;
	I1 = round_key_buffer;
    L1 = length(round_key_buffer);
    I2 = round_key_5;
    L2 = length(round_key_5);
    M1 = 1;
    cntr = 16;
    do record_6 until ce;
    ar = dm(I1,M1);
record_6:    dm(I2,M1) = ar;
//---------Key 6---------//
	sr1 = 0x20;
	call RotWord;
	call Sbox;
	call Rcon;
	call Solve;
	I1 = round_key_buffer;
    L1 = length(round_key_buffer);
    I2 = round_key_6;
    L2 = length(round_key_6);
    M1 = 1;
    cntr = 16;
    do record_7 until ce;
    ar = dm(I1,M1);
record_7:    dm(I2,M1) = ar;
//---------Key 7---------//
	sr1 = 0x40;
	call RotWord;
	call Sbox;
	call Rcon;
	call Solve;
	I1 = round_key_buffer;
    L1 = length(round_key_buffer);
    I2 = round_key_7;
    L2 = length(round_key_7);
    M1 = 1;
    cntr = 16;
    do record_8 until ce;
    ar = dm(I1,M1);
record_8:    dm(I2,M1) = ar;
//---------Key 8---------//
	sr1 = 0x80;
	call RotWord;
	call Sbox;
	call Rcon;
	call Solve;
	I1 = round_key_buffer;
    L1 = length(round_key_buffer);
    I2 = round_key_8;
    L2 = length(round_key_8);
    M1 = 1;
    cntr = 16;
    do record_9 until ce;
    ar = dm(I1,M1);
record_9:    dm(I2,M1) = ar;
//---------Key 9---------//
	sr1 = 0x1b;
	call RotWord;
	call Sbox;
	call Rcon;
	call Solve;
	I1 = round_key_buffer;
    L1 = length(round_key_buffer);
    I2 = round_key_9;
    L2 = length(round_key_9);
    M1 = 1;
    cntr = 16;
    do record_10 until ce;
    ar = dm(I1,M1);
record_10:    dm(I2,M1) = ar;
//---------Key 10---------//
	sr1 = 0x36;
	call RotWord;
	call Sbox;
	call Rcon;
	call Solve;
	I1 = round_key_buffer;
    L1 = length(round_key_buffer);
    I2 = round_key_10;
    L2 = length(round_key_10);
    M1 = 1;
    cntr = 16;
    do record_11 until ce;
    ar = dm(I1,M1);
record_11:  dm(I2,M1) = ar;
	rts;
	
Sbox:
	I2 = BUFF;
	L2 = length(BUFF);
	m2 = 1; 
	dm(I2,M2) = mr0;
	dm(I2,M2) = mr1;
	dm(I2,M2) = ax0;
	dm(I2,M2) = ar;
	i1 = BUFF;
	l1 = length(BUFF);
	m1 = 1;
	i2 = B;
	l2 = length(B);
	i3 = BUFF1;
	l3 = length(BUFF1);
	m3 = 1;
	cntr = 4;
	do sub until CE;
	si = dm(i1,m1);
	m2 = si;
	modify(i2,m2);
	sr0 = dm(i2,m1);
	dm(i3,m3) = sr0;
sub: 
	i2 = B; 
	rts;
RotWord:	
	I1 = round_key_buffer;
	L1 = length(round_key_buffer);
	m1 = 4;
	m2 = 3;
	modify(I1,m2);
	ar  = dm(I1,m1);
	mr0 = dm(I1,m1);
	mr1 = dm(I1,m1);
	ax0 = dm(I1,m1);
	rts;
Rcon:
	I1 = round_key_buffer;
	L1 = length(round_key_buffer);
	I2 = BUFF1;
	l2 = length(BUFF1);
	M1 = 4;
	M2 = 1;
	M3 = 3;
	ar = dm(I1,M1);
	ay0 =dm(I2,M2);
	ar = ar xor ay0;
	ay0 = sr1;
	ar = ar xor ay0;
	modify(I2,M3);
	dm(I2,M2) = ar;
	cntr = 3;
	do word until ce;
	ar = dm(I2,M2);
	ay0 = dm(I1,M1);
	ar = ar xor ay0; 
	modify(I2,M3);
	word: dm(I2,M2) = ar;
	rts;
Solve:
	I3 = round_key_buffer;
	L3 = length(round_key_buffer);
	m3 = 1;
	m2 = 4;
	ay0 = dm(I2,M3);
	ay1 = dm(I2,M3);
	my0 = dm(I2,M3);
	my1 = dm(I2,M3);
	dm(I3,M2)=ay0;
	dm(I3,M2)=ay1;
	dm(I3,M2)=my0;
	dm(I3,M2)=my1;
	modify(I3,M3);
	modify(I1,M3);
	ar = dm(I1,M2);
	ar = ar xor ay0;
	dm(I3,M2) = ar;
	ar = dm(I1,M2);
	ar = ar xor ay1;
	dm(I3,M2)=ar;
	ar = dm(I1,M2);
	ay0 = my0;
	ar = ar xor ay0;
	dm(I3,M2)=ar;
	ar = dm(I1,M2);
	ay1 = my1;
	ar = ar xor ay1;
	dm(I3,M2)=ar;
	modify(I1,M3);
	ay0 = dm(I3,M2);
	ay1 = dm(I3,M2);
	my0 = dm(I3,M2);
	my1 = dm(I3,M2);
	modify(I3,M3);
	ar = dm(I1,M2);
	ar = ar xor ay0;
	dm(I3,M2) = ar;
	ar = dm(I1,M2);
	ar = ar xor ay1;
	dm(I3,M2)=ar;
	ar = dm(I1,M2);
	ay0 = my0;
	ar = ar xor ay0;
	dm(I3,M2)=ar;
	ar = dm(I1,M2);
	ay1 = my1;
	ar = ar xor ay1;
	dm(I3,M2)=ar;
	modify(I1,M3);
	ay0 = dm(I3,M2);
	ay1 = dm(I3,M2);
	my0 = dm(I3,M2);
	my1 = dm(I3,M2);
	modify(I3,M3);
	ar = dm(I1,M2);
	ar = ar xor ay0;
	dm(I3,M2) = ar;
	ar = dm(I1,M2);
	ar = ar xor ay1;
	dm(I3,M2)=ar;
	ar = dm(I1,M2);
	ay0 = my0;
	ar = ar xor ay0;
	dm(I3,M2)=ar;
	ar = dm(I1,M2);
	ay1 = my1;
	ar = ar xor ay1;
	dm(I3,M2)=ar;
	rts;
//-------------------------//	
//      Sub bytes step     //
//-------------------------//		
subbyte: 
	I1 = message;
	l1 = length(message);
	M1 = 1;
	I2 = B;
	L2 = length(B);
	I3 = SubByte;
	L3 = length(SubByte);
	M3 = 1;
	cntr = 16;
	do sub_1 until CE;
	si = dm(I1,M1);
	M2 = si;
	modify(I2,M2);
	sr0 = dm(I2,M1);
	dm(I3,M3) = sr0; 
sub_1: 
	I2 = B;
	rts;
//-------------------------//
//    Shift bytes step     //
//-------------------------//
shiftbyte:
//------First string------//
	i1 = SubByte;
	l1 = length(SubByte);
	m1 = 1;
	i2 = ShiftByte;
	l2 = length(ShiftByte);
	m2 = 1;
	sr1 = dm(i1,m1);
	sr = lshift sr1 by 8 (hi);
	si = dm(i1,m1);
	sr = sr or lshift si by 0 (hi);
	ar = sr1;
	sr0 = dm(i1,m1);
	sr = lshift sr0 by 8 (lo);
	si = dm(i1,m1);
	sr = sr or lshift si by 0 (lo);
	sr = sr or lshift ar by 0 (hi);
	ax0 = ar;
	ay0 = b#1111111100000000;
	ar = ax0 and ay0;
	mr0 = sr0;
	sr = lshift ar by -8(hi);
	dm (i2,m2)= sr1;
	ay0 = b#0000000011111111;
	ar = ax0 and ay0;
	dm (i2,m2)= ar;
	ax0 = mr0;
	ay0 = b#1111111100000000;
	ar = ax0 and ay0;
	mr0 = sr0;
	sr = lshift ar by -8(hi);
	dm (i2,m2)= sr1;
	ay0 = b#0000000011111111;
	ar = ax0 and ay0;
	dm (i2,m2)= ar;
//------Second string------//
	sr1 = dm(i1,m1);
	sr = lshift sr1 by 8 (hi);
	si = dm(i1,m1);
	sr = sr or lshift si by 0 (hi);
	ar = sr1;
	sr0 = dm(i1,m1);
	sr = lshift sr0 by 8 (lo);
	si = dm(i1,m1);
	sr = sr or lshift si by 0 (lo);
	sr = sr or lshift ar by 0 (hi);
	mr0 = sr0;
	mr1= sr1;
	sr = lshift mr0 by 8(LO);
    sr=sr or lshift mr1 by 8 (HI);
    sr=sr or lshift mr1 by - 8(lo);
	ax0 = sr1;
	ay0 = b#1111111100000000;
	ar = ax0 and ay0;
	mr0 = sr0;
	sr = lshift ar by -8(hi);
	dm (i2,m2)= sr1;
	ay0 = b#0000000011111111;
	ar = ax0 and ay0;
	dm (i2,m2)= ar;
	ax0 = mr0;
	ay0 = b#1111111100000000;
	ar = ax0 and ay0;
	mr0 = sr0;
	sr = lshift ar by -8(hi);
	dm (i2,m2)= sr1;
	ay0 = b#0000000011111111;
	ar = ax0 and ay0;
	dm (i2,m2)= ar;
//------Third  string------//
	sr1 = dm(i1,m1);
	sr = lshift sr1 by 8 (hi);
	si = dm(i1,m1);
	sr = sr or lshift si by 0 (hi);
	ar = sr1;
	sr0 = dm(i1,m1);
	sr = lshift sr0 by 8 (lo);
	si = dm(i1,m1);
	sr = sr or lshift si by 0 (lo);
	sr = sr or lshift ar by 0 (hi);
	mr0 = sr0;
	mr1= sr1;
	sr = lshift mr0 by 16(LO);
    sr=sr or lshift mr1 by 0  (lo);
	ax0 = sr1;
	ay0 = b#1111111100000000;
	ar = ax0 and ay0;
	mr0 = sr0;
	sr = lshift ar by -8(hi);
	dm (i2,m2)= sr1;
	ay0 = b#0000000011111111;
	ar = ax0 and ay0;
	dm (i2,m2)= ar;
	ax0 = mr0;
	ay0 = b#1111111100000000;
	ar = ax0 and ay0;
	mr0 = sr0;
	sr = lshift ar by -8(hi);
	dm (i2,m2)= sr1;
	ay0 = b#0000000011111111;
	ar = ax0 and ay0;
	dm (i2,m2)= ar;
//-------Fourth string-------//
	sr1 = dm(i1,m1);
	sr = lshift sr1 by 8 (hi);
	si = dm(i1,m1);
	sr = sr or lshift si by 0 (hi);
	ar = sr1;
	sr0 = dm(i1,m1);
	sr = lshift sr0 by 8 (lo);
	si = dm(i1,m1);
	sr = sr or lshift si by 0 (lo);
	sr = sr or lshift ar by 0 (hi);
	mr0 = sr0;
	mr1= sr1;
	sr = lshift mr0 by 24(LO);
    sr=sr or lshift mr1 by -8  (hi);
    sr=sr or lshift mr1 by 8  (lo);
    sr=sr or lshift mr0 by -8  (lo);
	ax0 = sr1;
	ay0 = b#1111111100000000;
	ar = ax0 and ay0;
	mr0 = sr0;
	sr = lshift ar by -8(hi);
	dm (i2,m2)= sr1;
	ay0 = b#0000000011111111;
	ar = ax0 and ay0;
	dm (i2,m2)= ar;
	ax0 = mr0;
	ay0 = b#1111111100000000;
	ar = ax0 and ay0;
	mr0 = sr0;
	sr = lshift ar by -8(hi);
	dm (i2,m2)= sr1;
	ay0 = b#0000000011111111;
	ar = ax0 and ay0;
	dm (i2,m2)= ar;
	rts;
//-------------------------//
//     Mix bytes step      //
//-------------------------//
mixcolumns: 
	I3 = message;
	L3 = length(message);
	M3 = 4;
	I0 = ShiftByte;
	L0 = length(ShiftByte);
	M0 = 4;
	I1 = matr;
	L1 = length(matr);
	M1 = 1;
	cntr = 4;
do final until ce;
	I2 = MixColumns;
	L2 = length(MixColumns);
	M2 = 1;
	cntr = 16;
	do data_list until ce;
		call multiply_num;
	data_list:	dm(I2,M2) = ar;
			I2 = MixColumns;
			L2 = length(MixColumns);
			M2 = 1;
			call additional;
			modify(I3,M1);
			modify(I0,M1);
final:		nop;			
	rts;		
multiply_num:
    ar = dm(I0,M0);
    af = pass ar;
    ar = ar + af;
    mr = 0;
    mr0 = dm(I1,M1);
    call multiply;
    rts;
multiply:
    dis ar_sat;
    ay0 = 0;
    af = pass ay0;
    ay1 = 6;
    sr0 = 1;
    se =  1;
    ay0 = sr0;
    none = mr0 and ay0;
    if ne af = pass ar;
    cntr = 7;
    do return until ce;
    sr = lshift sr0 (lo), ay0 = ar;
    ar = ar + ay0, ay0 = sr0;
    if ac ar = ar xor ay1;
    none = mr0 and ay0;
    if ne af = ar xor af;
return: nop;
    ar = pass af;
    sr = lshift ar by -1 (lo);
    ar = sr0;
    af = tstbit 0x9 of ar;
    if ne jump sdvig;
    ay1 = dm(p);
    ar = ar xor ay1;
    af = tstbit 0x8 of ar;
    if ne ar = ar xor ay1;
    rts; 
sdvig: nop;
	mr1 = dm(p);
	sr = lshift mr1 by 1 (lo);
	ay1 = sr0;
	ar = ar xor ay1;
	rts;
additional:
	ar = 0;
	cntr = 4;
	do vector until ce;
		cntr = 4;
		do add until ce;
		ay0 = dm(I2,M2);
		ar = ar xor ay0;
		add: nop;
		dm (I3,M3) = ar;
		ar = 0;	
	vector: nop;
	rts;
//-------Inpute Data-------//
input:
	I0 = message;
	L0 = length(message);
	M0 = 1;
	cntr = 16;
	do input_word until ce; 
		ar = io(1);
input_word:		dm(I0,M0)= ar;
	rts; 
