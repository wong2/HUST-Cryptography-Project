#include <gtk/gtk.h>
#include <glib.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define BLOCK_SIZE 64

void create_keys(char *key, char(*keys)[48]);
void des_block(char *message, char(*keys)[48], int loop, int type, char *result);
void des(char *message, int length, char *key, int loops, int type, char *result);
void ip_perm(char *arr, int type);
void left_shift_array(char *arr, int len, int left);
void reverse(char *arr, int begin, int end);
void feistel(char *r, char *k);

const char S[8][4][16] = {
    //S1
    {{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},  
     {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},  
     {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},  
     {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},  
    //S2  
    {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},  
     {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},  
     {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},  
     {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},  
     //S3  
    {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},  
     {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},  
     {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},  
     {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},  
     //S4  
    {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},  
     {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},  
     {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},  
     {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},  
     //S5  
    {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},  
     {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},  
     {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},  
     {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},  
     //S6  
    {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},  
     {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},  
     {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},  
     {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},  
     //S7  
    {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},  
     {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},  
     {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},  
     {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},  
     //S8  
    {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},  
     {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},  
     {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},  
     {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}};  

GtkWidget *entry_e_m, *entry_e_k , *view, *entry_e_c, *entry_d_m, *entry_d_k , *view2, *entry_d_c;

void MessageBox(GtkWindow *parentWindow, char *message, char *title)
{
	GtkWidget *dialog;
    dialog = gtk_message_dialog_new(parentWindow, GTK_DIALOG_MODAL, GTK_MESSAGE_INFO, GTK_BUTTONS_OK, "%s", message);
    gtk_window_set_title(GTK_WINDOW (dialog), title);
    gtk_dialog_run(GTK_DIALOG (dialog));
    gtk_widget_destroy (dialog);
}

void crypt(GtkWidget *widget, gpointer window)
{
	int i, j;
	const gchar *message = gtk_entry_get_text(GTK_ENTRY(entry_e_m));
	const gchar *key = gtk_entry_get_text(GTK_ENTRY(entry_e_k));
	int message_len = strlen(message);
	if(!message_len){
		MessageBox(GTK_WINDOW(window), "请输入明文!", "错误");
		return;
	}
	if(message_len<8){
		MessageBox(GTK_WINDOW(window), "明文长度不能小于8个字节!", "错误");
		return;
	}
	int key_len = strlen(key);
	if(key_len != 8){
		MessageBox(GTK_WINDOW(window), "密钥长度错误，请输入8个英文字符或数字", "错误");
		return;
	}
	char *m = malloc(sizeof(char)*message_len*8);
	char *k = malloc(sizeof(char)*key_len*8);
    char *result = malloc(sizeof(char)*(message_len+1));

	for(i=0; i<message_len; i++)
		for(j=0; j<8; j++)
			m[i*8+j] = (message[i]>>(7-j))&1;
	for(i=0; i<key_len; i++)
		for(j=0; j<8; j++)
			k[i*8+j] = (key[i]>>(7-j))&1;

	des(m, message_len*8, k, 16, 0, result);

	int len_byte = message_len*2;
	char *cipher_text = malloc(len_byte+1);
	for(i=0; i<len_byte; i++){
		cipher_text[i] = 0x40; 
		for(j=0; j<4; j++)
			cipher_text[i] |= result[i*4+j]<<(3-j);
	}
	cipher_text[len_byte] = '\0';
	gtk_entry_set_text(GTK_ENTRY(entry_e_c), cipher_text);

	for(i=0; i<message_len*8; i++)
		result[i] = result[i]+'0';
	result[message_len*8] = '\0';

	GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));
	gtk_text_buffer_set_text(buffer, result, strlen(result));
}

void decrypt(GtkWidget *widget, gpointer window)
{
	int i, j;
	const gchar *message = gtk_entry_get_text(GTK_ENTRY(entry_d_m));
	const gchar *key = gtk_entry_get_text(GTK_ENTRY(entry_d_k));
	int message_len = strlen(message);
	if(!message_len){
		MessageBox(GTK_WINDOW(window), "请输入密文!", "错误");
		return;
	}
	int key_len = strlen(key);
	if(key_len != 8){
		MessageBox(GTK_WINDOW(window), "密钥长度错误，请输入8个英文字符或数字", "错误");
		return;
	}
	char *m = malloc(sizeof(char)*message_len*4);
	char *k = malloc(sizeof(char)*key_len*8);
    char *result = malloc(sizeof(char)*(message_len*4+1));

	for(i=0; i<message_len; i++)
		for(j=0; j<4; j++)
			m[i*4+j] = (message[i]>>(3-j))&1;
	for(i=0; i<key_len; i++)
		for(j=0; j<8; j++)
			k[i*8+j] = (key[i]>>(7-j))&1;
	
	des(m, message_len*4, k, 16, 1, result);
	
	int len_byte = message_len/2;
	char *cipher_text = malloc(len_byte+1);
	for(i=0; i<len_byte; i++){
		cipher_text[i] = 0;
		for(j=0; j<8; j++)
			cipher_text[i] |= result[i*8+j]<<(7-j);
	}
	cipher_text[len_byte] = '\0';
	gtk_entry_set_text(GTK_ENTRY(entry_d_c), cipher_text);

	for(i=0; i<message_len*4; i++)
		result[i] = result[i]+'0';
	result[message_len*4] = '\0';

	GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view2));
	gtk_text_buffer_set_text(buffer, result, strlen(result));
}

int main(int argc, char *argv[])
{
	gtk_init(&argc, &argv);
	
	GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
	gtk_window_set_default_size(GTK_WINDOW(window), 700, 500);
	gtk_window_set_title(GTK_WINDOW(window), "密码学实验：DES");

	GtkWidget *vbox = gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(window), vbox);

	GtkWidget *label_title_e = gtk_label_new("");
	gtk_label_set_markup(GTK_LABEL(label_title_e), "<big><b>加密</b></big>");
	gtk_box_pack_start(GTK_BOX(vbox), label_title_e, FALSE, FALSE, 30);

	GtkWidget *label_e_m = gtk_label_new("明文：");
	GtkWidget *label_e_k = gtk_label_new("密钥：");
	entry_e_m = gtk_entry_new();
	entry_e_k = gtk_entry_new();
	GtkWidget *button_e = gtk_button_new_with_label("加密！");
	GtkWidget *label_e_c = gtk_label_new("密文：");
	entry_e_c = gtk_entry_new();
	GtkWidget *label_e_b = gtk_label_new("二进制:");
	view = gtk_text_view_new();
	gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_CHAR);

	GtkWidget *table = gtk_table_new(3, 4, FALSE);
	gtk_box_pack_start(GTK_BOX(vbox), table, FALSE, TRUE, 0);
	gtk_table_attach(GTK_TABLE(table), label_e_m, 0, 1, 0, 1, 
		GTK_FILL | GTK_SHRINK, GTK_FILL | GTK_SHRINK, 5, 5);
	gtk_table_attach(GTK_TABLE(table), entry_e_m, 1, 2, 0, 1, 
		GTK_FILL | GTK_SHRINK, GTK_FILL | GTK_SHRINK, 5, 5);
	gtk_table_attach(GTK_TABLE(table), label_e_k, 0, 1, 1, 2, 
		GTK_FILL | GTK_SHRINK, GTK_FILL | GTK_SHRINK, 5, 5);
	gtk_table_attach(GTK_TABLE(table), entry_e_k, 1, 2, 1, 2, 
		GTK_FILL | GTK_SHRINK, GTK_FILL | GTK_SHRINK, 5, 5);
	gtk_table_attach(GTK_TABLE(table), button_e, 1, 2, 2, 3, 
		GTK_FILL | GTK_SHRINK, GTK_FILL | GTK_SHRINK, 5, 5);
	gtk_table_attach(GTK_TABLE(table), label_e_c, 2, 3, 0, 1, 
		GTK_FILL | GTK_SHRINK, GTK_FILL | GTK_SHRINK, 5, 5);
	gtk_table_attach(GTK_TABLE(table), entry_e_c, 3, 4, 0, 1, 
		GTK_FILL | GTK_SHRINK, GTK_FILL | GTK_SHRINK, 5, 5);
	gtk_table_attach(GTK_TABLE(table), label_e_b, 2, 3, 1, 2, 
		GTK_FILL | GTK_SHRINK, GTK_FILL | GTK_SHRINK, 20, 5);
	gtk_table_attach(GTK_TABLE(table), view, 3, 4, 1, 3, 
		GTK_FILL | GTK_SHRINK, GTK_FILL | GTK_SHRINK, 5, 5);
	
	gtk_editable_set_editable(GTK_EDITABLE(entry_e_c), FALSE);
	gtk_entry_set_width_chars(GTK_ENTRY(entry_e_c), 45);
	gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
	
	GtkWidget *label_title_d = gtk_label_new("");
	gtk_label_set_markup(GTK_LABEL(label_title_d), "<big><b>解密</b></big>");
	gtk_box_pack_start(GTK_BOX(vbox), label_title_d, FALSE, FALSE, 30);

	GtkWidget *label_d_m = gtk_label_new("密文：");
	GtkWidget *label_d_k = gtk_label_new("密钥：");
	entry_d_m = gtk_entry_new();
	entry_d_k = gtk_entry_new();
	GtkWidget *button_d = gtk_button_new_with_label("解密！");
	GtkWidget *label_d_c = gtk_label_new("明文：");
	entry_d_c = gtk_entry_new();
	GtkWidget *label_d_b = gtk_label_new("二进制:");
	view2 = gtk_text_view_new();
	gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view2), GTK_WRAP_CHAR);

	GtkWidget *table2 = gtk_table_new(3, 4, FALSE);
	gtk_box_pack_start(GTK_BOX(vbox), table2, FALSE, TRUE, 0);
	gtk_table_attach(GTK_TABLE(table2), label_d_m, 0, 1, 0, 1, 
		GTK_FILL | GTK_SHRINK, GTK_FILL | GTK_SHRINK, 5, 5);
	gtk_table_attach(GTK_TABLE(table2), entry_d_m, 1, 2, 0, 1, 
		GTK_FILL | GTK_SHRINK, GTK_FILL | GTK_SHRINK, 5, 5);
	gtk_table_attach(GTK_TABLE(table2), label_d_k, 0, 1, 1, 2, 
		GTK_FILL | GTK_SHRINK, GTK_FILL | GTK_SHRINK, 5, 5);
	gtk_table_attach(GTK_TABLE(table2), entry_d_k, 1, 2, 1, 2, 
		GTK_FILL | GTK_SHRINK, GTK_FILL | GTK_SHRINK, 5, 5);
	gtk_table_attach(GTK_TABLE(table2), button_d, 1, 2, 2, 3, 
		GTK_FILL | GTK_SHRINK, GTK_FILL | GTK_SHRINK, 5, 5);
	gtk_table_attach(GTK_TABLE(table2), label_d_c, 2, 3, 0, 1, 
		GTK_FILL | GTK_SHRINK, GTK_FILL | GTK_SHRINK, 5, 5);
	gtk_table_attach(GTK_TABLE(table2), entry_d_c, 3, 4, 0, 1, 
		GTK_FILL | GTK_SHRINK, GTK_FILL | GTK_SHRINK, 5, 5);
	gtk_table_attach(GTK_TABLE(table2), label_d_b, 2, 3, 1, 2, 
		GTK_FILL | GTK_SHRINK, GTK_FILL | GTK_SHRINK, 20, 5);
	gtk_table_attach(GTK_TABLE(table2), view2, 3, 4, 1, 3, 
		GTK_FILL | GTK_SHRINK, GTK_FILL | GTK_SHRINK, 5, 5);
	
	gtk_editable_set_editable(GTK_EDITABLE(entry_d_c), FALSE);
	gtk_entry_set_width_chars(GTK_ENTRY(entry_d_c), 45);
	gtk_text_view_set_editable(GTK_TEXT_VIEW(view2), FALSE);
	
	g_signal_connect(G_OBJECT(window), "destroy", G_CALLBACK(gtk_main_quit), NULL);
	g_signal_connect(G_OBJECT(button_e), "clicked", G_CALLBACK(crypt), window);
	g_signal_connect(G_OBJECT(button_d), "clicked", G_CALLBACK(decrypt), window);
	gtk_widget_show_all(window);
	gtk_main();
	return 0;
}

void des(char *message, int length, char *key, int loops, int type, char *result)
{
	int i, j, remain;
	char padding[BLOCK_SIZE], tmp[BLOCK_SIZE];
	char keys[16][48];

	int loop = length/BLOCK_SIZE;

	create_keys(key, keys);

	i = 0;
	remain = length % BLOCK_SIZE;
	if(type == 0){
		while(i<loop){
			des_block(message+i*BLOCK_SIZE, keys, loops, type, result+i*BLOCK_SIZE);
			i++;
		}
		if(remain){
			for(j=0; j<BLOCK_SIZE-remain;j++)
				padding[j] = result[loop*BLOCK_SIZE+j-(BLOCK_SIZE-remain)];
			while(j<BLOCK_SIZE){
				padding[j] = message[loop*BLOCK_SIZE+j-(BLOCK_SIZE-remain)];
				j++;
			}
			des_block(padding, keys, loops, type, result+loop*BLOCK_SIZE-(BLOCK_SIZE-remain));
		}
	}
	else{
		if(remain){
			for(i=0; i<BLOCK_SIZE; i++)	
				padding[i] = message[length-BLOCK_SIZE+i];
			des_block(padding, keys, loops, type, tmp);
			for(i=0; i<remain; i++)
				result[loop*BLOCK_SIZE+i] = tmp[BLOCK_SIZE-remain+i];
			for(i=0; i<BLOCK_SIZE-remain; i++)
				message[loop*BLOCK_SIZE+i-(BLOCK_SIZE-remain)] = tmp[i];
		}
		i = 0;
		while(i<loop){
			des_block(message+i*BLOCK_SIZE, keys, loops, type, result+i*BLOCK_SIZE);
			i++;
		}
	}
}

void des_block(char *block, char(*keys)[48], int loops, int type, char *result)
{
	// type=0: 加密 type=1: 解密
	char L[32], R[32], tmp[32];
	int i, j;
	
	ip_perm(block, 0);

	for(i=0; i<64; i++)
	    (i<32?L:R)[i%32] = block[i];
    
    for(i=0; i<loops; i++){
        for(j=0; j<32; j++)    
            tmp[j] = R[j];
            feistel(R, keys[(15-2*i)*type+i]);
        for(j=0; j<32; j++)
            R[j] = (R[j]==L[j]?0:1);
        for(j=0; j<32; j++)
            L[j] = tmp[j];
    }
    for(i=0; i<64; i++)
        result[i] = (i<32?R:L)[i%32];
    ip_perm(result, 1);
}

void ip_perm(char *arr, int type)
{
    char tmp[64];
	unsigned char i, ip[2][64] = {
         {58, 50, 42, 34, 26, 18, 10, 2, 
	      60, 52, 44, 36, 28, 20, 12, 4, 
          62, 54, 46, 38, 30, 22, 14, 6, 
          64, 56, 48, 40, 32, 24, 16, 8, 
          57, 49, 41, 33, 25, 17, 9, 1, 
          59, 51, 43, 35, 27, 19, 11, 3, 
          61, 53, 45, 37, 29, 21, 13, 5, 
          63, 55, 47, 39, 31, 23, 15, 7},
		 {40, 8, 48, 16, 56, 24, 64, 32, 
		  39, 7, 47, 15, 55, 23, 63, 31, 
		  38, 6, 46, 14, 54, 22, 62, 30, 
		  37, 5, 45, 13, 53, 21, 61, 29, 
		  36, 4, 44, 12, 52, 20, 60, 28, 
		  35, 3, 43, 11, 51, 19, 59, 27, 
		  34, 2, 42, 10, 50, 18, 58, 26, 
		  33, 1, 41, 9, 49, 17, 57, 25}};
    for(i=0; i<64; i++)
        tmp[i] = arr[ip[type][i]-1];
    for(i=0; i<64; i++)
        arr[i] = tmp[i];
}

void create_keys(char *key, char(*keys)[48])
{
	char c[28], d[28], tmp;
	char left_bits[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
	unsigned char pc1[56] = {56,48,40,32,24,16,8,  
              0,57,49,41,33,25,17,  
              9,1,58,50,42,34,26,  
              18,10,2,59,51,43,35,  
              62,54,46,38,30,22,14,  
              6,61,53,45,37,29,21,  
              13,5,60,52,44,36,28,  
              20,12,4,27,19,11,3};  
	unsigned char pc2[48] = {13,16,10,23,0,4,2,27,  
              14,5,20,9,22,18,11,3,  
              25,7,15,6,26,19,12,1,  
              40,51,30,36,46,54,29,39,  
              50,44,32,46,43,48,38,55,  
              33,52,45,41,49,35,28,31};  
	int i, j;
	for(i=0; i<56; i++)
		(i<28?c:d)[i%28] = key[pc1[i]];
        
    for(i=0; i<16; i++){
    	left_shift_array(c, 28, left_bits[i]);
		left_shift_array(d, 28, left_bits[i]);
		for(j=0; j<48; j++){
			tmp = pc2[j];
			keys[i][j] = (tmp<28?c:d)[tmp%28];
		}
	}
}

void left_shift_array(char *arr, int len, int left)
{
	reverse(arr, 0, left-1);
	reverse(arr, left, len-1);
	reverse(arr, 0, len-1);
}

void reverse(char *arr, int begin, int end)
{
	char tmp;
	for(; begin<end; begin++, end--)
	{
		tmp = arr[begin];
		arr[begin] = arr[end];
		arr[end] = tmp;
	}
}

void feistel(char *r, char *key)
{
	char after_e[48], after_s[48];
	int i, j, k, row, col;
	char in_s;
	char p[32] = {16, 7, 20, 21, 29, 12, 28, 17,
				  1, 15, 23, 26, 5, 18, 31, 10, 
				  2, 8, 24, 14, 32, 27, 3, 9, 
				  19, 13, 30, 6, 22, 11, 4, 25};				  	
	
	for(i=0; i<8; i++)
		for(j=0; j<6; j++)
			after_e[i*6+j] = r[(31+i*4+j)%32];
	
	for(i=0; i<48; i++)
		after_e[i] = (after_e[i]==key[i]?0:1);

	for(i=0; i<8; i++){
		col = 0;
		for(j=1; j<4; j++)
			col += after_e[i*8+j] * (2<<(3-j));
		col += after_e[i*8+4];
		row = after_e[i*8]*2+after_e[i*8+5];
		in_s = S[i][row][col];
		for(k=0; k<4; k++)
			after_s[i*4+k] = (in_s>>(3-k))&1;
	}
	
	for(i=0; i<32; i++)
		r[i] = after_s[p[i]-1];
}
